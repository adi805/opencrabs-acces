//! AC-006, AC-011, AC-012: the turn lane — the ACK carries the `seq` before
//! any provider call, a second send queues instead of forking a turn, and an
//! interrupt ends the named turn with a broadcast `turn.failed`.
//!
//! The relay is built over the placeholder provider, so no test here reaches
//! the network and none of them depend on a model's answer.

use crate::a2a::test_helpers::helpers;
use crate::db::models::Session;
use crate::db::repository::SessionRepository;
use crate::remote::admission::{Admission, TurnAdmission};
use crate::remote::events::{self, KIND_TURN_FAILED};
use crate::remote::pairing::PairingStore;
use crate::remote::relay::RelayState;
use crate::remote::seq::Replay;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

static NEXT_STORE: AtomicU64 = AtomicU64::new(0);

async fn relay() -> Arc<RelayState> {
    let n = NEXT_STORE.fetch_add(1, Ordering::SeqCst);
    let pairing = PairingStore::new(
        std::env::temp_dir().join(format!("oc-relay-turn-{}-{n}.json", std::process::id())),
    );
    RelayState::new(
        pairing,
        helpers::placeholder_service_context().await,
        helpers::placeholder_agent_service().await,
    )
    .into_arc()
}

async fn new_session(relay: &RelayState) -> Uuid {
    let repo = SessionRepository::new(relay.service.pool());
    let session = Session::new(Some("remote turn".to_string()), None, None);
    repo.create(&session).await.expect("create session");
    session.id
}

fn frames_from(relay: &RelayState, session: Uuid, from: u64) -> Vec<crate::remote::seq::Frame> {
    match relay.seq.for_session(session).replay(from) {
        Replay::Frames(frames) => frames,
        Replay::Gap { oldest_seq } => panic!("unexpected gap at {oldest_seq}"),
    }
}

#[tokio::test]
async fn ack_precedes_provider_call() {
    let relay = relay().await;
    let session = new_session(&relay).await;

    let outcome = relay
        .send(session, "hello".to_string(), Uuid::new_v4())
        .await
        .expect("send admitted");

    assert!(!outcome.duplicate, "a first send is not a retry");
    assert!(!outcome.queued, "the first send starts the turn");

    // The ACK seq is already a buffered frame, so nothing the provider does
    // can precede it.
    let frames = frames_from(&relay, session, outcome.seq - 1);
    let first = frames.first().expect("the user.message frame");
    assert_eq!(first.seq, outcome.seq);
    assert_eq!(first.kind, events::KIND_USER_MESSAGE);
    assert_eq!(first.payload["queued"], serde_json::json!(false));
}

#[tokio::test]
async fn a_retried_send_returns_the_same_seq() {
    let relay = relay().await;
    let session = new_session(&relay).await;
    let client_msg_id = Uuid::new_v4();

    let first = relay
        .send(session, "one".to_string(), client_msg_id)
        .await
        .expect("first send");
    let again = relay
        .send(session, "one".to_string(), client_msg_id)
        .await
        .expect("retry accepted");

    assert!(again.duplicate, "the retry is recognised, not re-run");
    assert_eq!(again.seq, first.seq, "the same seq, so clients dedupe");
}

#[test]
fn second_send_is_queued() {
    let admission = TurnAdmission::new(4);
    let session = Uuid::new_v4();

    let running = match admission.begin(session, Uuid::new_v4(), "one", 1_000) {
        Admission::Started { turn_id } => turn_id,
        _ => panic!("the first send must start the turn"),
    };
    let queued = match admission.begin(session, Uuid::new_v4(), "two", 1_001) {
        Admission::Queued { turn_id, position } => {
            assert_eq!(position, 1, "first in line");
            turn_id
        }
        _ => panic!("a second send must queue behind the running turn"),
    };

    assert_ne!(queued, running, "each send gets its own turn id");
    assert_eq!(admission.queue_len(session), 1, "exactly one turn waiting");
    assert_eq!(
        admission.running(session).map(|t| t.turn_id),
        Some(running),
        "the running turn is unchanged"
    );
}

#[test]
fn a_full_lane_reports_busy_instead_of_dropping() {
    let admission = TurnAdmission::new(1);
    let session = Uuid::new_v4();

    let running = match admission.begin(session, Uuid::new_v4(), "one", 1_000) {
        Admission::Started { turn_id } => turn_id,
        _ => panic!("first send starts"),
    };
    assert!(matches!(
        admission.begin(session, Uuid::new_v4(), "two", 1_001),
        Admission::Queued { .. }
    ));
    match admission.begin(session, Uuid::new_v4(), "three", 1_002) {
        Admission::Busy { turn_id } => assert_eq!(turn_id, running),
        _ => panic!("a full queue must report the blocking turn"),
    }
}

#[tokio::test]
async fn interrupt_broadcasts() {
    let relay = relay().await;
    let session = new_session(&relay).await;

    let turn_id =
        match relay
            .admission
            .begin(session, Uuid::new_v4(), "hi", crate::remote::now_secs())
        {
            Admission::Started { turn_id } => turn_id,
            _ => panic!("the turn must start"),
        };

    assert!(relay.interrupt(session, turn_id), "the running turn is hit");

    let frames = frames_from(&relay, session, 0);
    let last = frames.last().expect("an interrupt publishes a frame");
    assert_eq!(last.kind, KIND_TURN_FAILED);
    assert_eq!(last.payload["reason"], serde_json::json!("interrupted"));
    assert_eq!(last.payload["turn_id"], serde_json::json!(turn_id));
    assert!(
        relay.admission.running(session).is_none(),
        "the slot is free again"
    );
}

#[tokio::test]
async fn a_stale_interrupt_does_not_kill_the_next_turn() {
    let relay = relay().await;
    let session = new_session(&relay).await;

    let first =
        match relay
            .admission
            .begin(session, Uuid::new_v4(), "one", crate::remote::now_secs())
        {
            Admission::Started { turn_id } => turn_id,
            _ => panic!("first turn starts"),
        };
    assert!(relay.interrupt(session, first));
    let second =
        match relay
            .admission
            .begin(session, Uuid::new_v4(), "two", crate::remote::now_secs())
        {
            Admission::Started { turn_id } => turn_id,
            _ => panic!("second turn starts once the slot is free"),
        };

    assert!(
        !relay.interrupt(session, first),
        "the stale id no longer names a turn"
    );
    assert_eq!(
        relay.admission.running(session).map(|t| t.turn_id),
        Some(second),
        "the replacement turn survives"
    );
}
