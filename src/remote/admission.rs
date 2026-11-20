//! Turn admission: one running turn per session, a bounded queue behind it,
//! idempotent sends, interrupt, and the restart sweep.
//!
//! The rules this module enforces:
//!
//! - **One running turn per session.** A second `session/send` never starts
//!   a parallel agent loop; it queues, or is refused with `TURN_BUSY` once
//!   the queue is at its bound.
//! - **Idempotent by `client_msg_id`.** A client that retries after a
//!   dropped response gets the original `seq` back with `duplicate: true`
//!   instead of posting the message twice.
//! - **Interrupt names a turn.** `session/interrupt` only cancels the turn
//!   it names, so a stale interrupt from another device cannot kill the
//!   turn that started after it.
//! - **Restart sweeps, never resumes.** A turn that was running when the
//!   process died is cleared at boot: its side effects may have half-run,
//!   so the engine reports the turn as failed rather than replaying it.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use tokio::sync::oneshot;
use uuid::Uuid;

/// How many sends may wait behind the running turn before `TURN_BUSY`.
pub const DEFAULT_QUEUE_BOUND: usize = 4;

/// How many `(client_msg_id → seq)` pairs a session remembers for
/// idempotency. A retry that arrives after this many later sends is treated
/// as new; that is a deliberate bound, not an oversight.
pub const DEDUPE_WINDOW: usize = 256;

/// Lifecycle of a session's turn slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnState {
    /// Nothing running, nothing queued.
    Idle,
    /// A turn is executing.
    Running,
    /// A turn runs and at least one send waits behind it.
    Queued,
}

impl TurnState {
    /// Wire string used by `session/list`.
    pub fn as_str(self) -> &'static str {
        match self {
            TurnState::Idle => "idle",
            TurnState::Running => "running",
            TurnState::Queued => "queued",
        }
    }
}

/// The outcome of asking to start a turn.
#[derive(Debug, Clone, PartialEq)]
pub enum Admission {
    /// The turn slot was free; start this turn now.
    Started { turn_id: Uuid },
    /// A turn runs; this one waits at `position` (1-based).
    Queued { turn_id: Uuid, position: usize },
    /// This `client_msg_id` was already accepted; `seq` is its original.
    Duplicate { seq: u64 },
    /// The queue is at its bound; the named turn blocks it.
    Busy { turn_id: Uuid },
}

/// A send waiting behind the running turn.
#[derive(Debug, Clone, PartialEq)]
pub struct QueuedTurn {
    pub turn_id: Uuid,
    pub client_msg_id: Uuid,
    pub text: String,
}

/// A turn that holds the slot.
#[derive(Debug, Clone, PartialEq)]
pub struct RunningTurn {
    pub turn_id: Uuid,
    pub client_msg_id: Uuid,
    /// Unix seconds when the turn started, for the restart sweep.
    pub started_at: u64,
}

#[derive(Debug, Default)]
struct SessionSlot {
    running: Option<RunningTurn>,
    queue: VecDeque<QueuedTurn>,
    /// `(client_msg_id, seq)`, oldest first, bounded by [`DEDUPE_WINDOW`].
    seen: VecDeque<(Uuid, u64)>,
}

/// Per-session turn slots.
#[derive(Debug)]
pub struct TurnAdmission {
    slots: Mutex<HashMap<Uuid, SessionSlot>>,
    queue_bound: usize,
}

impl Default for TurnAdmission {
    fn default() -> Self {
        Self::new(DEFAULT_QUEUE_BOUND)
    }
}

impl TurnAdmission {
    /// Admission with an explicit queue bound (tests and tuning).
    pub fn new(queue_bound: usize) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            queue_bound: queue_bound.max(1),
        }
    }

    /// Ask to start a turn for `client_msg_id`.
    ///
    /// `now` is unix seconds, injected so tests do not sleep.
    pub fn begin(&self, session_id: Uuid, client_msg_id: Uuid, text: &str, now: u64) -> Admission {
        let mut map = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let slot = map.entry(session_id).or_default();

        if let Some((_, seq)) = slot.seen.iter().find(|(id, _)| *id == client_msg_id) {
            return Admission::Duplicate { seq: *seq };
        }

        let turn_id = Uuid::new_v4();
        match &slot.running {
            None => {
                slot.running = Some(RunningTurn {
                    turn_id,
                    client_msg_id,
                    started_at: now,
                });
                Admission::Started { turn_id }
            }
            Some(_) if slot.queue.len() < self.queue_bound => {
                slot.queue.push_back(QueuedTurn {
                    turn_id,
                    client_msg_id,
                    text: text.to_string(),
                });
                Admission::Queued {
                    turn_id,
                    position: slot.queue.len(),
                }
            }
            Some(running) => Admission::Busy {
                turn_id: running.turn_id,
            },
        }
    }

    /// Remember the `seq` a send was assigned, so a retry is recognised.
    pub fn remember_seq(&self, session_id: Uuid, client_msg_id: Uuid, seq: u64) {
        let mut map = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let slot = map.entry(session_id).or_default();
        if slot.seen.iter().any(|(id, _)| *id == client_msg_id) {
            return;
        }
        slot.seen.push_back((client_msg_id, seq));
        while slot.seen.len() > DEDUPE_WINDOW {
            slot.seen.pop_front();
        }
    }

    /// The seq recorded for a retried send, if it is still in the window.
    pub fn remembered_seq(&self, session_id: Uuid, client_msg_id: Uuid) -> Option<u64> {
        let map = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&session_id)?
            .seen
            .iter()
            .find(|(id, _)| *id == client_msg_id)
            .map(|(_, seq)| *seq)
    }

    /// Mark the running turn finished and promote the next queued one.
    ///
    /// Returns the promoted turn, if any; the caller starts it. A finish for
    /// a turn that is not the running one (a stale completion after an
    /// interrupt) is ignored and returns `None`.
    pub fn finish(&self, session_id: Uuid, turn_id: Uuid) -> Option<QueuedTurn> {
        let mut map = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let slot = map.get_mut(&session_id)?;
        if slot.running.as_ref().map(|r| r.turn_id) != Some(turn_id) {
            return None;
        }
        slot.running = None;
        let next = slot.queue.pop_front();
        if let Some(t) = &next {
            slot.running = Some(RunningTurn {
                turn_id: t.turn_id,
                client_msg_id: t.client_msg_id,
                started_at: crate::remote::now_secs(),
            });
        }
        next
    }

    /// Drop the named turn from the slot: cancel the running one, or remove
    /// a queued one. Returns true when something was actually removed.
    pub fn interrupt(&self, session_id: Uuid, turn_id: Uuid) -> bool {
        let mut map = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slot) = map.get_mut(&session_id) else {
            return false;
        };
        if slot.running.as_ref().map(|r| r.turn_id) == Some(turn_id) {
            slot.running = None;
            return true;
        }
        let before = slot.queue.len();
        slot.queue.retain(|t| t.turn_id != turn_id);
        slot.queue.len() != before
    }

    /// The turn holding the slot, if any.
    pub fn running(&self, session_id: Uuid) -> Option<RunningTurn> {
        self.slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&session_id)?
            .running
            .clone()
    }

    /// Sends waiting behind the running turn.
    pub fn queue_len(&self, session_id: Uuid) -> usize {
        self.slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&session_id)
            .map(|s| s.queue.len())
            .unwrap_or(0)
    }

    /// Turn state for `session/list`.
    pub fn state(&self, session_id: Uuid) -> TurnState {
        let map = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(&session_id) {
            None => TurnState::Idle,
            Some(slot) => match (&slot.running, slot.queue.len()) {
                (None, _) => TurnState::Idle,
                (Some(_), 0) => TurnState::Running,
                (Some(_), _) => TurnState::Queued,
            },
        }
    }

    /// Clear every running turn, returning the `(session, turn)` pairs that
    /// were abandoned so the caller can mark them failed. Called once at
    /// boot: a turn cannot survive a process restart.
    pub fn sweep_on_restart(&self) -> Vec<(Uuid, Uuid)> {
        let mut map = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let mut swept = Vec::new();
        for (session_id, slot) in map.iter_mut() {
            if let Some(running) = slot.running.take() {
                swept.push((*session_id, running.turn_id));
            }
            slot.queue.clear();
        }
        map.retain(|_, slot| {
            slot.running.is_some() || !slot.queue.is_empty() || !slot.seen.is_empty()
        });
        swept
    }

    /// Clear one session's slot entirely (session deleted).
    pub fn forget(&self, session_id: Uuid) {
        self.slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&session_id);
    }
}

/// Decision a device sends for a pending tool approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// Run the tool.
    Approve,
    /// Run the tool and every later one in this turn.
    Always,
    /// Refuse the tool.
    Deny,
}

impl ApprovalDecision {
    /// Parse the wire value of `session/approve`.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "approve" => Some(Self::Approve),
            "always" => Some(Self::Always),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }

    /// `(approved, always_approve)` as the engine's callback expects.
    pub fn as_engine_flags(self) -> (bool, bool) {
        match self {
            Self::Approve => (true, false),
            Self::Always => (true, true),
            Self::Deny => (false, false),
        }
    }
}

/// Pending approvals, one per `request_id`, answerable from any device.
///
/// The engine registers a request and awaits the receiver; whichever device
/// answers first wins, and the entry is removed so a second answer is a
/// no-op rather than a second decision.
#[derive(Debug, Default)]
pub struct Approvals {
    pending: Mutex<HashMap<Uuid, (Uuid, oneshot::Sender<ApprovalDecision>)>>,
}

impl Approvals {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pending approval for `session_id`. Dropping the returned
    /// receiver (turn cancelled) makes a later decision a no-op.
    pub fn register(
        &self,
        session_id: Uuid,
        request_id: Uuid,
    ) -> oneshot::Receiver<ApprovalDecision> {
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(request_id, (session_id, tx));
        rx
    }

    /// Answer a pending approval. Returns the device id that decided, or
    /// `None` when the request is unknown, already answered, or belongs to
    /// another session.
    pub fn decide(
        &self,
        session_id: Uuid,
        request_id: Uuid,
        decision: ApprovalDecision,
    ) -> Option<()> {
        let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let (owner, tx) = map.remove(&request_id)?;
        if owner != session_id {
            // Put it back: a wrong-session answer must not consume it.
            map.insert(request_id, (owner, tx));
            return None;
        }
        let _ = tx.send(decision);
        Some(())
    }

    /// Pending count for one session.
    pub fn pending_for(&self, session_id: Uuid) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|(owner, _)| *owner == session_id)
            .count()
    }

    /// Drop every pending approval of a session (turn cancelled).
    pub fn clear_session(&self, session_id: Uuid) {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (owner, _)| *owner != session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_send_starts_and_second_queues() {
        let adm = TurnAdmission::new(2);
        let s = Uuid::new_v4();
        let a = adm.begin(s, Uuid::new_v4(), "one", 100);
        assert!(matches!(a, Admission::Started { .. }));
        let b = adm.begin(s, Uuid::new_v4(), "two", 101);
        assert!(matches!(b, Admission::Queued { position: 1, .. }));
        assert_eq!(adm.state(s), TurnState::Queued);
    }

    #[test]
    fn queue_bound_reports_busy_with_the_blocking_turn() {
        let adm = TurnAdmission::new(1);
        let s = Uuid::new_v4();
        let Admission::Started { turn_id } = adm.begin(s, Uuid::new_v4(), "one", 1) else {
            panic!("expected start");
        };
        assert!(matches!(
            adm.begin(s, Uuid::new_v4(), "two", 2),
            Admission::Queued { .. }
        ));
        assert_eq!(
            adm.begin(s, Uuid::new_v4(), "three", 3),
            Admission::Busy { turn_id }
        );
    }

    #[test]
    fn retry_of_an_accepted_send_returns_the_original_seq() {
        let adm = TurnAdmission::new(2);
        let s = Uuid::new_v4();
        let client = Uuid::new_v4();
        assert!(matches!(
            adm.begin(s, client, "hi", 1),
            Admission::Started { .. }
        ));
        adm.remember_seq(s, client, 42);
        assert_eq!(
            adm.begin(s, client, "hi", 2),
            Admission::Duplicate { seq: 42 }
        );
        assert_eq!(adm.remembered_seq(s, client), Some(42));
    }

    #[test]
    fn dedupe_window_is_bounded() {
        let adm = TurnAdmission::new(1);
        let s = Uuid::new_v4();
        let first = Uuid::new_v4();
        adm.remember_seq(s, first, 1);
        for i in 0..DEDUPE_WINDOW {
            adm.remember_seq(s, Uuid::new_v4(), i as u64 + 2);
        }
        assert_eq!(adm.remembered_seq(s, first), None, "evicted by the window");
    }

    #[test]
    fn finish_promotes_the_next_queued_turn() {
        let adm = TurnAdmission::new(4);
        let s = Uuid::new_v4();
        let Admission::Started { turn_id } = adm.begin(s, Uuid::new_v4(), "one", 1) else {
            panic!("expected start");
        };
        let Admission::Queued {
            turn_id: queued, ..
        } = adm.begin(s, Uuid::new_v4(), "two", 2)
        else {
            panic!("expected queue");
        };
        let promoted = adm.finish(s, turn_id).expect("promoted");
        assert_eq!(promoted.turn_id, queued);
        assert_eq!(adm.running(s).map(|r| r.turn_id), Some(queued));
        assert_eq!(adm.state(s), TurnState::Running);
    }

    #[test]
    fn stale_finish_does_not_clear_a_newer_turn() {
        let adm = TurnAdmission::new(2);
        let s = Uuid::new_v4();
        let Admission::Started { turn_id: first } = adm.begin(s, Uuid::new_v4(), "one", 1) else {
            panic!("expected start");
        };
        adm.interrupt(s, first);
        let Admission::Started { turn_id: second } = adm.begin(s, Uuid::new_v4(), "two", 2) else {
            panic!("expected start after interrupt");
        };
        assert!(adm.finish(s, first).is_none());
        assert_eq!(adm.running(s).map(|r| r.turn_id), Some(second));
    }

    #[test]
    fn interrupt_only_hits_the_named_turn() {
        let adm = TurnAdmission::new(4);
        let s = Uuid::new_v4();
        let Admission::Started { turn_id } = adm.begin(s, Uuid::new_v4(), "one", 1) else {
            panic!("expected start");
        };
        assert!(!adm.interrupt(s, Uuid::new_v4()), "unknown turn");
        assert!(adm.interrupt(s, turn_id));
        assert_eq!(adm.state(s), TurnState::Idle);
    }

    #[test]
    fn restart_sweep_clears_running_turns_and_reports_them() {
        let adm = TurnAdmission::new(2);
        let s1 = Uuid::new_v4();
        let s2 = Uuid::new_v4();
        let Admission::Started { turn_id: t1 } = adm.begin(s1, Uuid::new_v4(), "a", 1) else {
            panic!()
        };
        adm.begin(s1, Uuid::new_v4(), "b", 2);
        let Admission::Started { turn_id: t2 } = adm.begin(s2, Uuid::new_v4(), "c", 3) else {
            panic!()
        };
        let mut swept = adm.sweep_on_restart();
        swept.sort_unstable();
        let mut expected = vec![(s1, t1), (s2, t2)];
        expected.sort_unstable();
        assert_eq!(swept, expected);
        assert_eq!(adm.state(s1), TurnState::Idle);
        assert_eq!(adm.queue_len(s1), 0);
    }

    #[tokio::test]
    async fn approval_first_answer_wins() {
        let approvals = Approvals::new();
        let s = Uuid::new_v4();
        let req = Uuid::new_v4();
        let rx = approvals.register(s, req);
        assert_eq!(approvals.pending_for(s), 1);
        assert!(
            approvals
                .decide(s, req, ApprovalDecision::Approve)
                .is_some()
        );
        assert_eq!(rx.await.unwrap(), ApprovalDecision::Approve);
        assert!(
            approvals.decide(s, req, ApprovalDecision::Deny).is_none(),
            "second answer is a no-op"
        );
        assert_eq!(approvals.pending_for(s), 0);
    }

    #[tokio::test]
    async fn approval_from_the_wrong_session_is_refused_and_kept() {
        let approvals = Approvals::new();
        let owner = Uuid::new_v4();
        let other = Uuid::new_v4();
        let req = Uuid::new_v4();
        let _rx = approvals.register(owner, req);
        assert!(
            approvals
                .decide(other, req, ApprovalDecision::Approve)
                .is_none()
        );
        assert_eq!(approvals.pending_for(owner), 1);
        assert!(
            approvals
                .decide(owner, req, ApprovalDecision::Deny)
                .is_some()
        );
    }

    #[test]
    fn decision_flags_match_the_engine_callback() {
        assert_eq!(ApprovalDecision::Approve.as_engine_flags(), (true, false));
        assert_eq!(ApprovalDecision::Always.as_engine_flags(), (true, true));
        assert_eq!(ApprovalDecision::Deny.as_engine_flags(), (false, false));
        assert_eq!(
            ApprovalDecision::parse("always"),
            Some(ApprovalDecision::Always)
        );
        assert_eq!(ApprovalDecision::parse("yes"), None);
    }
}
