//! Relay state: the shared handle every remote handler works through.
//!
//! One [`RelayState`] lives on the gateway. It owns the sequence store, the
//! subscriber registry, turn admission, pending approvals, the pairing store
//! and the agent service, and it is the only place a turn is started from a
//! remote client.
//!
//! Flow of one remote turn:
//!
//! 1. `session/send` validates the session and asks [`TurnAdmission`] for the
//!    turn slot. The user message is published as `user.message` and its
//!    `seq` returned to the client, so the sender sees its own message in the
//!    same sequence everyone else reads.
//! 2. [`RelayState::spawn_turn`] runs the agent loop with a progress callback
//!    that maps `ProgressEvent` → frame → seq → fanout, and an approval
//!    callback that publishes `approval.requested` and awaits any device.
//! 3. On completion the turn publishes `turn.finished` / `turn.failed`, frees
//!    the slot, and promotes the next queued send if there is one.
//!
//! Cancellation is per turn id, never per session: a stale interrupt from a
//! device that lost the race cannot kill the turn that replaced it.

use crate::brain::agent::service::{
    AgentService, ApprovalCallback, ProgressCallback, ProgressEvent, ToolApprovalInfo,
};
use crate::db::repository::SessionRepository;
use crate::remote::admission::{ApprovalDecision, Approvals, QueuedTurn, TurnAdmission, TurnState};
use crate::remote::errors::RemoteError;
use crate::remote::events::{self, map_progress};
use crate::remote::pairing::PairingStore;
use crate::remote::registry::{SessionRegistry, Subscription};
use crate::remote::seq::{Frame, Replay, SeqStore};
use crate::services::ServiceContext;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// How long a tool approval waits for a device before it is denied. A turn
/// must never hang forever on a client that went away mid-approval.
pub const APPROVAL_TIMEOUT_SECS: u64 = 300;

/// What `session/send` decided.
#[derive(Debug, Clone, PartialEq)]
pub struct SendOutcome {
    /// Sequence number assigned to the user message.
    pub seq: u64,
    /// True when the message waits behind a running turn.
    pub queued: bool,
    /// True when this `client_msg_id` was already accepted.
    pub duplicate: bool,
}

/// Deterministic device key for the in-memory registries.
///
/// Pairing identities are 12-character hash prefixes (strings), while the
/// registry keys on `Uuid`. A v5 hash gives a stable one-way mapping so the
/// two can never drift, and the string id stays the wire identity.
pub fn device_key(device_id: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, device_id.as_bytes())
}

/// Everything the remote surface shares.
pub struct RelayState {
    pub seq: Arc<SeqStore>,
    pub registry: Arc<SessionRegistry>,
    pub admission: Arc<TurnAdmission>,
    pub approvals: Arc<Approvals>,
    pub pairing: PairingStore,
    pub service: ServiceContext,
    pub agent: Arc<AgentService>,
    cancels: Mutex<HashMap<Uuid, CancellationToken>>,
}

impl std::fmt::Debug for RelayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayState")
            .field("sessions_tracked", &self.seq.len())
            .field("subscribers", &self.registry.total_subscribers())
            .finish_non_exhaustive()
    }
}

impl RelayState {
    /// Build the relay over an existing agent service and pairing store.
    pub fn new(pairing: PairingStore, service: ServiceContext, agent: Arc<AgentService>) -> Self {
        Self {
            seq: Arc::new(SeqStore::new()),
            registry: Arc::new(SessionRegistry::new()),
            admission: Arc::new(TurnAdmission::default()),
            approvals: Arc::new(Approvals::new()),
            pairing,
            service,
            agent,
            cancels: Mutex::new(HashMap::new()),
        }
    }

    /// Wrap in an `Arc` for the callbacks and spawned turns.
    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Publish one event: assign `seq`, buffer it, fan it out.
    ///
    /// A frame too large for the byte budget is not buffered and not sent; it
    /// returns `None` so the caller can decide (artifact routes carry bytes
    /// out of band). Everything else is fire-and-forget by design: a slow
    /// client is the registry's problem, never the turn's.
    pub fn publish(&self, session_id: Uuid, kind: &str, payload: Value) -> Option<Frame> {
        let frame = self
            .seq
            .for_session(session_id)
            .publish(kind, payload)
            .ok()?;
        self.registry.publish(session_id, Arc::new(frame.clone()));
        Some(frame)
    }

    /// Current turn state for `session/list`.
    pub fn turn_state(&self, session_id: Uuid) -> TurnState {
        self.admission.state(session_id)
    }

    /// Attach a device to a session's live stream.
    ///
    /// Returns the frames the client missed followed by a live subscription.
    /// A `resume_from` older than the ring is refused with
    /// [`RemoteError::ResumeGap`] carrying `oldest_seq`, so the client reloads
    /// history instead of silently skipping events.
    pub fn attach(
        &self,
        session_id: Uuid,
        resume_from: Option<u64>,
        device_id: &str,
    ) -> Result<(Vec<Frame>, Subscription), RemoteError> {
        let sequence = self.seq.for_session(session_id);
        let replay = match resume_from {
            Some(from) => match sequence.replay(from) {
                Replay::Frames(frames) => frames,
                Replay::Gap { oldest_seq } => return Err(RemoteError::ResumeGap { oldest_seq }),
            },
            None => Vec::new(),
        };
        let sub = self.registry.subscribe(session_id, device_key(device_id));
        Ok((replay, sub))
    }

    /// Accept a user message: validate, admit, publish, and start the turn
    /// when the slot was free.
    pub async fn send(
        self: &Arc<Self>,
        session_id: Uuid,
        text: String,
        client_msg_id: Uuid,
    ) -> Result<SendOutcome, RemoteError> {
        if text.trim().is_empty() {
            return Err(RemoteError::ValidationError {
                field: "text".into(),
                reason: "must not be empty".into(),
            });
        }
        let repo = SessionRepository::new(self.service.pool());
        if repo
            .find_by_id(session_id)
            .await
            .map_err(|e| RemoteError::internal(e.to_string()))?
            .is_none()
        {
            return Err(RemoteError::SessionNotFound { session_id });
        }

        let now = crate::remote::now_secs();
        match self.admission.begin(session_id, client_msg_id, &text, now) {
            crate::remote::admission::Admission::Duplicate { seq } => Ok(SendOutcome {
                seq,
                queued: false,
                duplicate: true,
            }),
            crate::remote::admission::Admission::Busy { turn_id } => {
                Err(RemoteError::TurnBusy { turn_id })
            }
            crate::remote::admission::Admission::Queued { turn_id, .. } => {
                let frame = self
                    .publish(
                        session_id,
                        events::KIND_USER_MESSAGE,
                        json!({
                            "text": text,
                            "client_msg_id": client_msg_id,
                            "queued": true,
                            "turn_id": turn_id,
                        }),
                    )
                    .ok_or_else(|| RemoteError::internal("user message frame too large"))?;
                self.admission
                    .remember_seq(session_id, client_msg_id, frame.seq);
                Ok(SendOutcome {
                    seq: frame.seq,
                    queued: true,
                    duplicate: false,
                })
            }
            crate::remote::admission::Admission::Started { turn_id } => {
                let frame = self
                    .publish(
                        session_id,
                        events::KIND_USER_MESSAGE,
                        json!({
                            "text": text,
                            "client_msg_id": client_msg_id,
                            "queued": false,
                            "turn_id": turn_id,
                        }),
                    )
                    .ok_or_else(|| RemoteError::internal("user message frame too large"))?;
                self.admission
                    .remember_seq(session_id, client_msg_id, frame.seq);
                self.spawn_turn(session_id, turn_id, text);
                Ok(SendOutcome {
                    seq: frame.seq,
                    queued: false,
                    duplicate: false,
                })
            }
        }
    }

    /// Cancel the named turn. Returns false when it is not the running or a
    /// queued turn of this session.
    pub fn interrupt(&self, session_id: Uuid, turn_id: Uuid) -> bool {
        let token = {
            let mut cancels = self.cancels.lock().unwrap_or_else(|e| e.into_inner());
            cancels.remove(&turn_id)
        };
        let removed = self.admission.interrupt(session_id, turn_id);
        if let Some(t) = token {
            t.cancel();
        }
        if removed {
            self.publish(
                session_id,
                events::KIND_TURN_FAILED,
                json!({ "turn_id": turn_id, "reason": "interrupted" }),
            );
        }
        removed
    }

    /// Record that every attached client rendered through `seq`.
    pub fn ack(&self, session_id: Uuid, seq: u64) {
        self.seq.for_session(session_id).ack(seq);
    }

    /// Answer a pending approval from any device.
    pub fn approve(
        &self,
        session_id: Uuid,
        request_id: Uuid,
        decision: ApprovalDecision,
    ) -> Result<(), RemoteError> {
        match self.approvals.decide(session_id, request_id, decision) {
            Some(()) => Ok(()),
            None => Err(RemoteError::ValidationError {
                field: "request_id".into(),
                reason: "unknown, already answered, or from another session".into(),
            }),
        }
    }

    /// Start one turn. Never blocks the caller; the turn runs detached and
    /// reports through the sequence.
    pub fn spawn_turn(self: &Arc<Self>, session_id: Uuid, turn_id: Uuid, text: String) {
        let token = CancellationToken::new();
        {
            let mut cancels = self.cancels.lock().unwrap_or_else(|e| e.into_inner());
            cancels.insert(turn_id, token.clone());
        }
        self.publish(
            session_id,
            events::KIND_TURN_STARTED,
            json!({ "turn_id": turn_id }),
        );

        let relay = Arc::clone(self);
        tokio::spawn(async move {
            // The same pre-turn hygiene the GUI runs (#2697, #2756): a resend
            // of the text an unanswered turn left behind must not stack a
            // second copy of the question in history.
            let messages = crate::services::MessageService::new(relay.service.clone());
            crate::services::turn_dedup::drop_unanswered_duplicate(&messages, session_id, &text)
                .await;
            let progress = progress_callback(&relay);
            let approval = approval_callback(&relay);
            let result = relay
                .agent
                .send_message_with_tools_and_callback(
                    session_id,
                    text,
                    None,
                    Some(token),
                    Some(approval),
                    Some(progress),
                    "remote",
                    None,
                    None,
                )
                .await;

            relay
                .cancels
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&turn_id);
            relay.approvals.clear_session(session_id);
            match result {
                Ok(_) => {
                    relay.publish(
                        session_id,
                        events::KIND_TURN_FINISHED,
                        json!({ "turn_id": turn_id }),
                    );
                }
                Err(e) => {
                    relay.publish(
                        session_id,
                        events::KIND_TURN_FAILED,
                        json!({ "turn_id": turn_id, "reason": e.to_string() }),
                    );
                }
            }
            if let Some(QueuedTurn {
                turn_id: next_id,
                text: next_text,
                ..
            }) = relay.admission.finish(session_id, turn_id)
            {
                relay.spawn_turn(session_id, next_id, next_text);
            }
        });
    }

    /// Clear abandoned turns at boot and report them.
    ///
    /// A turn cannot survive a process restart: its tool call may have
    /// half-run, so the engine reports it failed instead of replaying it.
    pub fn sweep_on_restart(&self) -> Vec<(Uuid, Uuid)> {
        let swept = self.admission.sweep_on_restart();
        for (session_id, turn_id) in &swept {
            self.publish(
                *session_id,
                events::KIND_TURN_FAILED,
                json!({ "turn_id": turn_id, "reason": "engine restarted" }),
            );
        }
        swept
    }
}

/// Progress callback that maps every engine event into the session sequence.
fn progress_callback(relay: &Arc<RelayState>) -> ProgressCallback {
    let relay = Arc::clone(relay);
    Arc::new(move |session_id: Uuid, event: ProgressEvent| {
        let mapped = map_progress(&event);
        relay.publish(session_id, mapped.kind, mapped.payload);
    })
}

/// Approval callback: publish the request, wait for any device, deny on
/// timeout so a turn never hangs on an absent client.
fn approval_callback(relay: &Arc<RelayState>) -> ApprovalCallback {
    let relay = Arc::clone(relay);
    Arc::new(move |info: ToolApprovalInfo| {
        let relay = Arc::clone(&relay);
        Box::pin(async move {
            let request_id = Uuid::new_v4();
            let rx = relay.approvals.register(info.session_id, request_id);
            relay.publish(
                info.session_id,
                events::KIND_APPROVAL_REQUESTED,
                json!({
                    "request_id": request_id,
                    "tool": info.tool_name,
                    "input": info.tool_input,
                    "description": info.tool_description,
                    "capabilities": info.capabilities,
                }),
            );
            let wait = std::time::Duration::from_secs(APPROVAL_TIMEOUT_SECS);
            match tokio::time::timeout(wait, rx).await {
                Ok(Ok(decision)) => Ok(decision.as_engine_flags()),
                _ => Ok((false, false)),
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_key_is_stable_and_distinct() {
        assert_eq!(device_key("abc"), device_key("abc"));
        assert_ne!(device_key("abc"), device_key("abd"));
    }

    #[test]
    fn approval_timeout_is_bounded() {
        assert!(APPROVAL_TIMEOUT_SECS >= 30 && APPROVAL_TIMEOUT_SECS <= 900);
    }
}
