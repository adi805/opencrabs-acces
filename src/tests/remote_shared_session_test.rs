//! AC-007: two clients attached to one session see one identical, gap-free
//! `(seq, kind)` stream for the whole turn.
//!
//! The property under test is not "delivery works" but "delivery is the SAME
//! to both surfaces": two phones rendering different event orders would make
//! the shared session a lie. So the assertion compares the two vectors
//! element-for-element rather than checking each for monotonicity alone.

use crate::remote::registry::SessionRegistry;
use crate::remote::seq::SessionSeq;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// One turn's worth of frames, in the order the relay would emit them.
const TURN_KINDS: [&str; 6] = [
    "turn.started",
    "thinking",
    "text.delta",
    "text.delta",
    "tool.started",
    "turn.finished",
];

#[tokio::test]
async fn two_clients_same_sequence() {
    let session = Uuid::new_v4();
    let registry = SessionRegistry::new();
    let seq = SessionSeq::default();
    let mut phone = registry.subscribe(session, Uuid::new_v4());
    let mut laptop = registry.subscribe(session, Uuid::new_v4());

    for (i, kind) in TURN_KINDS.iter().enumerate() {
        let frame = seq
            .publish(*kind, json!({ "i": i }))
            .expect("frame fits the buffer");
        registry.publish(session, Arc::new(frame));
    }

    let mut seen_phone = Vec::new();
    while let Ok(frame) = phone.rx.try_recv() {
        seen_phone.push((frame.seq, frame.kind.clone()));
    }
    let mut seen_laptop = Vec::new();
    while let Ok(frame) = laptop.rx.try_recv() {
        seen_laptop.push((frame.seq, frame.kind.clone()));
    }

    assert_eq!(seen_phone, seen_laptop, "both clients saw one stream");
    assert_eq!(seen_phone.len(), TURN_KINDS.len(), "nothing was dropped");
    for (idx, (seq, kind)) in seen_phone.iter().enumerate() {
        assert_eq!(*seq, idx as u64 + 1, "seq starts at 1 and never skips");
        assert_eq!(kind, TURN_KINDS[idx]);
    }
}

#[tokio::test]
async fn a_client_joining_mid_turn_sees_the_rest_of_the_sequence() {
    let session = Uuid::new_v4();
    let registry = SessionRegistry::new();
    let seq = SessionSeq::default();
    let mut early = registry.subscribe(session, Uuid::new_v4());

    for i in 0..3 {
        let frame = seq
            .publish("text.delta", json!({ "i": i }))
            .expect("publish");
        registry.publish(session, Arc::new(frame));
    }

    // A second device attaches late and asks for everything after seq 1.
    let late_from = match seq.replay(1) {
        crate::remote::seq::Replay::Frames(frames) => frames,
        crate::remote::seq::Replay::Gap { oldest_seq } => {
            panic!("buffer still holds seq 2, got gap at {oldest_seq}")
        }
    };
    let mut late = registry.subscribe(session, Uuid::new_v4());
    let frame = seq.publish("turn.finished", json!({})).expect("publish");
    registry.publish(session, Arc::new(frame));

    let mut early_seqs = Vec::new();
    while let Ok(f) = early.rx.try_recv() {
        early_seqs.push(f.seq);
    }
    let mut late_seqs: Vec<u64> = late_from.iter().map(|f| f.seq).collect();
    while let Ok(f) = late.rx.try_recv() {
        late_seqs.push(f.seq);
    }

    assert_eq!(early_seqs, vec![1, 2, 3, 4]);
    assert_eq!(late_seqs, vec![2, 3, 4], "replay plus live, no duplicate");
}
