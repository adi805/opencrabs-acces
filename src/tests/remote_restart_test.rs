//! AC-035: after an engine restart no turn is reported as still running.
//!
//! A turn cannot survive the process: its tool call may have half-run, so the
//! engine reports it failed instead of replaying it. The test pins both halves
//! of that contract — the swept turn is published as failed, and the lane is
//! free for the next send.

use crate::a2a::test_helpers::helpers;
use crate::db::models::Session;
use crate::db::repository::SessionRepository;
use crate::remote::admission::Admission;
use crate::remote::events::KIND_TURN_FAILED;
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
        std::env::temp_dir().join(format!("oc-relay-restart-{}-{n}.json", std::process::id())),
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
    let session = Session::new(Some("restart".to_string()), None, None);
    repo.create(&session).await.expect("create session");
    session.id
}

#[tokio::test]
async fn no_phantom_turn_after_restart() {
    let relay = relay().await;
    let session = new_session(&relay).await;

    let turn_id = match relay
        .admission
        .begin(session, Uuid::new_v4(), "in flight", crate::remote::now_secs())
    {
        Admission::Started { turn_id } => turn_id,
        _ => panic!("the turn must start"),
    };

    let swept = relay.sweep_on_restart();
    assert_eq!(swept, vec![(session, turn_id)], "the abandoned turn");
    assert!(
        relay.admission.running(session).is_none(),
        "no turn survives a restart"
    );

    let frames = match relay.seq.for_session(session).replay(0) {
        Replay::Frames(frames) => frames,
        Replay::Gap { oldest_seq } => panic!("unexpected gap at {oldest_seq}"),
    };
    let last = frames.last().expect("the sweep publishes a frame");
    assert_eq!(last.kind, KIND_TURN_FAILED);
    assert_eq!(last.payload["reason"], serde_json::json!("engine restarted"));
    assert_eq!(last.payload["turn_id"], serde_json::json!(turn_id));
}

#[tokio::test]
async fn a_second_sweep_finds_nothing() {
    let relay = relay().await;
    let session = new_session(&relay).await;
    match relay
        .admission
        .begin(session, Uuid::new_v4(), "x", crate::remote::now_secs())
    {
        Admission::Started { .. } => {}
        _ => panic!("the turn must start"),
    }

    assert_eq!(relay.sweep_on_restart().len(), 1);
    assert!(
        relay.sweep_on_restart().is_empty(),
        "sweeping twice must not re-report"
    );
}

#[tokio::test]
async fn the_lane_accepts_a_new_turn_after_the_sweep() {
    let relay = relay().await;
    let session = new_session(&relay).await;
    match relay
        .admission
        .begin(session, Uuid::new_v4(), "before", crate::remote::now_secs())
    {
        Admission::Started { .. } => {}
        _ => panic!("the turn must start"),
    }
    relay.sweep_on_restart();

    match relay
        .admission
        .begin(session, Uuid::new_v4(), "after", crate::remote::now_secs())
    {
        Admission::Started { .. } => {}
        _ => panic!("a swept session must accept a new turn"),
    }
}
