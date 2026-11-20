//! Per-session monotonic event sequence and bounded replay buffer.
//!
//! One [`SessionSeq`] per session owns:
//!
//! - a monotonic `seq` counter that never repeats and never wraps in
//!   practice (a `u64` incremented once per frame would need 5.8e11 frames
//!   per second for 100 years to wrap),
//! - a ring buffer of the most recent frames, bounded by BOTH an event
//!   count ([`DEFAULT_MAX_EVENTS`]) and a byte budget
//!   ([`DEFAULT_MAX_BYTES`]), whichever trips first,
//! - the resume decision: a client that says "I have everything up to
//!   `seq = N`" gets either the contiguous tail or a [`Replay::Gap`]
//!   telling it where replay begins, so it can reload history instead of
//!   silently skipping events.
//!
//! Frames are `(kind, payload)` pairs rather than a serialised enum: the
//! engine's `ProgressEvent` is deliberately not `Serialize` (it carries
//! provider handles), so the relay maps it at the boundary and this module
//! stays ignorant of the agent internals.

use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Default ring capacity in frames. Five thousand frames is roughly an
/// hour of a busy turn at typical event rates and costs little.
pub const DEFAULT_MAX_EVENTS: usize = 5_000;

/// Default ring capacity in bytes of `kind + payload`. Eight megabytes
/// holds the full five thousand frames even when every payload is a large
/// tool result, and bounds a session's relay memory regardless.
pub const DEFAULT_MAX_BYTES: usize = 8 * 1024 * 1024;

/// One event as it travels to clients.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    /// Monotonic per-session sequence number, starting at 1.
    pub seq: u64,
    /// Event kind: `turn.started`, `text.delta`, `tool.started`, ...
    pub kind: String,
    /// Opaque payload; the relay maps `ProgressEvent` into this shape.
    pub payload: Value,
}

impl Frame {
    /// Build a frame with an explicit seq (tests and replay fixtures).
    pub fn new(seq: u64, kind: impl Into<String>, payload: Value) -> Self {
        Self {
            seq,
            kind: kind.into(),
            payload,
        }
    }

    /// Bytes this frame occupies in the ring, counted the same way the
    /// budget is charged: kind length plus serialised payload length.
    pub fn cost_bytes(&self) -> usize {
        self.kind.len() + self.payload.to_string().len()
    }
}

/// The answer to "give me everything after `resume_from`".
#[derive(Debug, Clone, PartialEq)]
pub enum Replay {
    /// Contiguous frames, oldest first. Empty when the client is current.
    Frames(Vec<Frame>),
    /// The requested point is older than the buffer: the client must
    /// reload history from `oldest_seq - 1` and resume from there.
    Gap { oldest_seq: u64 },
}

/// Why a publish was refused.
#[derive(Debug, Clone, PartialEq)]
pub enum PublishError {
    /// A single frame alone exceeds the byte budget; it is not buffered.
    FrameTooLarge { cost: usize, max_bytes: usize },
}

/// Monotonic sequence plus bounded ring for one session.
///
/// Every method takes `&self`; interior mutability is a `Mutex` over the
/// ring only, so `publish` stays callable from a sync progress callback.
#[derive(Debug)]
pub struct SessionSeq {
    next_seq: Mutex<u64>,
    ring: Mutex<VecDeque<Frame>>,
    bytes: Mutex<usize>,
    max_events: usize,
    max_bytes: usize,
    /// Highest seq a client has acknowledged, so the ring can drop frames
    /// every attached client already rendered.
    acked: Mutex<u64>,
}

impl Default for SessionSeq {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_EVENTS, DEFAULT_MAX_BYTES)
    }
}

impl SessionSeq {
    /// New buffer with explicit caps. Both caps are clamped to at least 1 so
    /// a misconfigured zero cannot make every publish fail.
    pub fn new(max_events: usize, max_bytes: usize) -> Self {
        Self {
            next_seq: Mutex::new(1),
            ring: Mutex::new(VecDeque::with_capacity(max_events.min(64))),
            bytes: Mutex::new(0),
            max_events: max_events.max(1),
            max_bytes: max_bytes.max(1),
            acked: Mutex::new(0),
        }
    }

    /// Append a frame and return it with its assigned seq.
    ///
    /// Evicts oldest-first until both caps hold. A frame larger than the
    /// whole byte budget is refused with [`PublishError::FrameTooLarge`]:
    /// buffering it would evict everything else and still overflow, so the
    /// caller must send it out of band (artifact route) instead.
    pub fn publish(&self, kind: impl Into<String>, payload: Value) -> Result<Frame, PublishError> {
        let mut next = self.next_seq.lock().unwrap_or_else(|e| e.into_inner());
        let frame = Frame::new(*next, kind, payload);
        let cost = frame.cost_bytes();
        if cost > self.max_bytes {
            return Err(PublishError::FrameTooLarge {
                cost,
                max_bytes: self.max_bytes,
            });
        }
        *next += 1;

        let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        let mut bytes = self.bytes.lock().unwrap_or_else(|e| e.into_inner());
        ring.push_back(frame.clone());
        *bytes += cost;
        while ring.len() > self.max_events || *bytes > self.max_bytes {
            match ring.pop_front() {
                Some(old) => *bytes = bytes.saturating_sub(old.cost_bytes()),
                None => break,
            }
        }
        Ok(frame)
    }

    /// The seq the next publish will take.
    pub fn next_seq(&self) -> u64 {
        *self.next_seq.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Highest seq published so far (`0` when nothing has been).
    pub fn latest_seq(&self) -> u64 {
        self.next_seq().saturating_sub(1)
    }

    /// Oldest seq still buffered, `None` when the ring is empty.
    pub fn oldest_seq(&self) -> Option<u64> {
        self.ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .front()
            .map(|f| f.seq)
    }

    /// Frames currently buffered.
    pub fn len(&self) -> usize {
        self.ring.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// True when nothing is buffered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes currently charged against the budget.
    pub fn bytes(&self) -> usize {
        *self.bytes.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Everything after `resume_from`, oldest first.
    ///
    /// `resume_from` is the last seq the client already has (exclusive).
    /// Returns [`Replay::Gap`] when that point fell out of the ring, so the
    /// caller answers `RESUME_GAP` with `details.oldest_seq` instead of
    /// pretending the client is current.
    pub fn replay(&self, resume_from: u64) -> Replay {
        // Read the counter BEFORE taking the ring lock: `publish` takes
        // next_seq then ring, so the reverse order here would deadlock the
        // first concurrent publish and replay of one session.
        let latest = self.latest_seq();
        let ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        if ring.is_empty() {
            // Nothing buffered: a client that is at or past the latest seq
            // is current; anything behind it lost events it cannot get.
            return if resume_from >= latest {
                Replay::Frames(Vec::new())
            } else {
                Replay::Gap {
                    oldest_seq: latest.saturating_add(1),
                }
            };
        }
        let oldest = ring.front().map(|f| f.seq).unwrap_or(1);
        if resume_from.saturating_add(1) < oldest {
            return Replay::Gap { oldest_seq: oldest };
        }
        let frames = ring
            .iter()
            .filter(|f| f.seq > resume_from)
            .cloned()
            .collect();
        Replay::Frames(frames)
    }

    /// Record that every attached client has rendered through `seq`, and
    /// drop frames at or below it from the ring.
    ///
    /// The ack is monotonic: an older ack never re-widens the ring.
    pub fn ack(&self, seq: u64) {
        let mut acked = self.acked.lock().unwrap_or_else(|e| e.into_inner());
        if seq <= *acked {
            return;
        }
        *acked = seq;
        let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        let mut bytes = self.bytes.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(front) = ring.front() {
            if front.seq > seq {
                break;
            }
            let old = ring.pop_front().expect("front checked");
            *bytes = bytes.saturating_sub(old.cost_bytes());
        }
    }

    /// Highest acknowledged seq.
    pub fn acked_seq(&self) -> u64 {
        *self.acked.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drop every buffered frame, keeping the sequence monotonic. Used when
    /// a session is deleted; a re-created session starts from 1.
    pub fn clear(&self) {
        self.ring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        *self.bytes.lock().unwrap_or_else(|e| e.into_inner()) = 0;
    }
}

/// Session-id → sequence registry.
///
/// Cheap to clone via `Arc`; the map itself is behind one mutex because a
/// publish is a short critical section and contention is per-session, not
/// global, at realistic fanout.
#[derive(Debug, Default)]
pub struct SeqStore {
    sessions: Mutex<HashMap<Uuid, Arc<SessionSeq>>>,
}

impl SeqStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The sequence for `session_id`, created on first use.
    pub fn for_session(&self, session_id: Uuid) -> Arc<SessionSeq> {
        let mut map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(session_id)
            .or_insert_with(|| Arc::new(SessionSeq::default()))
            .clone()
    }

    /// Existing sequence, without creating one.
    pub fn get(&self, session_id: Uuid) -> Option<Arc<SessionSeq>> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&session_id)
            .cloned()
    }

    /// Forget a session's buffer entirely (session deleted or swept).
    pub fn remove(&self, session_id: Uuid) -> Option<Arc<SessionSeq>> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&session_id)
    }

    /// Session ids currently tracked.
    pub fn session_ids(&self) -> Vec<Uuid> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .copied()
            .collect()
    }

    /// Tracked session count.
    pub fn len(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// True when no session is tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn seq_with(events: usize, bytes: usize) -> SessionSeq {
        SessionSeq::new(events, bytes)
    }

    #[test]
    fn seq_is_monotonic_from_one() {
        let s = seq_with(10, 1 << 20);
        for expected in 1..=5u64 {
            let f = s.publish("text.delta", json!({"t": "x"})).unwrap();
            assert_eq!(f.seq, expected);
        }
        assert_eq!(s.latest_seq(), 5);
        assert_eq!(s.next_seq(), 6);
    }

    #[test]
    fn eviction_is_oldest_first_by_count() {
        let s = seq_with(3, 1 << 20);
        for i in 0..5 {
            s.publish("text.delta", json!({"i": i})).unwrap();
        }
        assert_eq!(s.len(), 3);
        assert_eq!(s.oldest_seq(), Some(3));
        assert_eq!(s.latest_seq(), 5);
    }

    #[test]
    fn eviction_respects_byte_budget() {
        // Each frame costs roughly 40+ bytes; a 200-byte budget holds a few.
        let s = seq_with(1000, 200);
        for _ in 0..20 {
            s.publish("tool.completed", json!({"summary": "0123456789"})).unwrap();
        }
        assert!(s.bytes() <= 200, "bytes {} over budget", s.bytes());
        assert!(s.len() < 20);
    }

    #[test]
    fn frame_larger_than_budget_is_refused_without_advancing_seq() {
        let s = seq_with(10, 32);
        let err = s.publish("artifact", json!({"blob": "x".repeat(200)})).unwrap_err();
        assert!(matches!(err, PublishError::FrameTooLarge { .. }));
        assert_eq!(s.latest_seq(), 0);
        assert!(s.is_empty());
    }

    #[test]
    fn replay_returns_only_frames_after_the_cursor() {
        let s = seq_with(10, 1 << 20);
        for i in 1..=5 {
            s.publish("text.delta", json!({"i": i})).unwrap();
        }
        match s.replay(2) {
            Replay::Frames(f) => {
                assert_eq!(f.len(), 3);
                assert_eq!(f[0].seq, 3);
                assert_eq!(f[2].seq, 5);
            }
            other => panic!("expected frames, got {other:?}"),
        }
        match s.replay(5) {
            Replay::Frames(f) => assert!(f.is_empty()),
            other => panic!("expected empty frames, got {other:?}"),
        }
    }

    #[test]
    fn replay_after_eviction_returns_gap_with_oldest_seq() {
        let s = seq_with(3, 1 << 20);
        for i in 0..6 {
            s.publish("text.delta", json!({"i": i})).unwrap();
        }
        // Buffer now holds 4,5,6. A client at seq 1 lost 2 and 3.
        assert_eq!(s.replay(1), Replay::Gap { oldest_seq: 4 });
        // A client exactly one behind the oldest is still contiguous.
        match s.replay(3) {
            Replay::Frames(f) => {
                assert_eq!(f.iter().map(|x| x.seq).collect::<Vec<_>>(), vec![4, 5, 6]);
            }
            other => panic!("expected contiguous frames, got {other:?}"),
        }
    }

    #[test]
    fn replay_on_empty_buffer_is_current_or_gap() {
        let s = seq_with(3, 1 << 20);
        assert_eq!(s.replay(0), Replay::Frames(Vec::new()));
        s.publish("a", json!({})).unwrap();
        s.clear();
        assert_eq!(s.replay(0), Replay::Gap { oldest_seq: 2 });
    }

    #[test]
    fn ack_trims_and_is_monotonic() {
        let s = seq_with(10, 1 << 20);
        for i in 0..5 {
            s.publish("text.delta", json!({"i": i})).unwrap();
        }
        s.ack(3);
        assert_eq!(s.acked_seq(), 3);
        assert_eq!(s.oldest_seq(), Some(4));
        s.ack(1); // older ack must not rewind
        assert_eq!(s.acked_seq(), 3);
        assert_eq!(s.oldest_seq(), Some(4));
        assert_eq!(s.replay(2), Replay::Gap { oldest_seq: 4 });
    }

    #[test]
    fn store_creates_once_and_forgets() {
        let store = SeqStore::new();
        let id = Uuid::new_v4();
        let a = store.for_session(id);
        a.publish("x", json!({})).unwrap();
        let b = store.for_session(id);
        assert_eq!(b.latest_seq(), 1, "same buffer, not a fresh one");
        assert_eq!(store.len(), 1);
        assert!(store.remove(id).is_some());
        assert!(store.get(id).is_none());
        assert!(store.is_empty());
    }
}
