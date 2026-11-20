//! AC-029: a client that stops ACKing is detached, and the other subscribers
//! keep receiving. The engine never blocks on a slow client.
//!
//! The assertion that matters is the second half: detaching the laggard must
//! not cost the healthy client a single frame.

use crate::remote::registry::{Delivery, SessionRegistry};
use crate::remote::seq::Frame;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

fn frame(seq: u64) -> Arc<Frame> {
    Arc::new(Frame::new(seq, "text.delta", json!({ "seq": seq })))
}

#[tokio::test]
async fn slow_client_detached() {
    // One slot of buffer and a short miss tolerance, so the test does not
    // have to publish 32 frames to trip the threshold.
    let registry = SessionRegistry::with_limits(1, 4);
    let session = Uuid::new_v4();
    let mut healthy = registry.subscribe(session, Uuid::new_v4());
    let _laggard = registry.subscribe(session, Uuid::new_v4());

    let mut healthy_frames = 0usize;
    let mut detached_at = None;
    for seq in 1..=10u64 {
        let outcomes = registry.publish(session, frame(seq));
        if let Some(Delivery::Lagging { skipped, .. }) = outcomes
            .iter()
            .find(|o| matches!(o, Delivery::Lagging { .. }))
        {
            detached_at = Some((seq, *skipped));
        }
        // The healthy client ACKs every frame immediately, as a live stream
        // draining its socket would.
        while healthy.rx.try_recv().is_ok() {
            healthy_frames += 1;
        }
    }

    let (seq, misses) = detached_at.expect("the laggard was detached");
    assert_eq!(misses, 4, "detached once the miss tolerance was reached");
    assert_eq!(seq, 5, "buffer filled at 1, then four misses");
    assert_eq!(healthy_frames, 10, "the healthy client lost nothing");
    assert_eq!(
        registry.subscribers(session).len(),
        1,
        "only the laggard was removed"
    );
}

#[tokio::test]
async fn detaching_the_laggard_keeps_the_others_attached() {
    let registry = SessionRegistry::with_limits(1, 2);
    let session = Uuid::new_v4();
    let mut first = registry.subscribe(session, Uuid::new_v4());
    let mut second = registry.subscribe(session, Uuid::new_v4());
    let _dead = registry.subscribe(session, Uuid::new_v4());

    for seq in 1..=6u64 {
        registry.publish(session, frame(seq));
        while first.rx.try_recv().is_ok() {}
        while second.rx.try_recv().is_ok() {}
    }

    assert_eq!(registry.devices(session).len(), 2, "two survivors");
    assert!(registry.publish(session, frame(99)).is_empty());
}

#[tokio::test]
async fn a_publish_to_an_empty_session_costs_nothing() {
    let registry = SessionRegistry::new();
    assert!(registry.publish(Uuid::new_v4(), frame(1)).is_empty());
    assert_eq!(registry.total_subscribers(), 0);
}
