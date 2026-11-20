//! AC-008, AC-009, AC-028: resume by `seq` replays exactly what was missed, an
//! evicted cursor produces an explicit `RESUME_GAP`, and repeated reconnects
//! neither lose nor duplicate a frame.
//!
//! These are the three ways a mobile client can be wrong about history, so
//! each gets its own test rather than one "reconnect works" assertion.

use crate::remote::seq::{Replay, SessionSeq};
use serde_json::json;

fn publish_upto(seq: &SessionSeq, n: u64) {
    for i in 1..=n {
        seq.publish("text.delta", json!({ "i": i }))
            .expect("frame fits the buffer");
    }
}

#[test]
fn replay_after_drop() {
    let seq = SessionSeq::default();
    publish_upto(&seq, 50);

    let replayed = match seq.replay(40) {
        Replay::Frames(frames) => frames,
        Replay::Gap { oldest_seq } => panic!("seq 40 is still buffered, got gap {oldest_seq}"),
    };

    let got: Vec<u64> = replayed.iter().map(|f| f.seq).collect();
    assert_eq!(got, (41..=50).collect::<Vec<u64>>(), "41..N exactly once");
}

#[test]
fn evicted_seq_returns_gap() {
    // A ten-frame ring cannot answer a client sitting at seq 5 once 20 have
    // been published.
    let seq = SessionSeq::new(10, 1024 * 1024);
    publish_upto(&seq, 20);

    match seq.replay(5) {
        Replay::Gap { oldest_seq } => {
            assert_eq!(oldest_seq, 11, "the oldest frame still held");
            assert!(
                oldest_seq > 6,
                "the client is told to reload history, not to skip ahead"
            );
        }
        Replay::Frames(frames) => panic!("expected a gap, got {} frames", frames.len()),
    }
}

#[test]
fn two_hundred_reconnects() {
    let seq = SessionSeq::default();
    let mut cursor = 0u64;
    let mut delivered: Vec<u64> = Vec::new();

    for _ in 0..200 {
        // Each reconnect publishes one more frame before the client returns,
        // which is what a real drop looks like: events keep happening.
        seq.publish("text.delta", json!({})).expect("publish");
        let replayed = match seq.replay(cursor) {
            Replay::Frames(frames) => frames,
            Replay::Gap { oldest_seq } => panic!("no eviction expected, gap at {oldest_seq}"),
        };
        for frame in replayed {
            delivered.push(frame.seq);
        }
        cursor = *delivered.last().expect("something was delivered");
    }

    assert_eq!(delivered.len(), 200, "every frame delivered exactly once");
    let mut sorted = delivered.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 200, "no duplicates across reconnects");
    assert_eq!(delivered, (1..=200).collect::<Vec<u64>>(), "no gaps");
}

#[test]
fn a_cursor_at_the_head_replays_nothing() {
    let seq = SessionSeq::default();
    publish_upto(&seq, 3);

    match seq.replay(3) {
        Replay::Frames(frames) => assert!(frames.is_empty(), "client is current"),
        Replay::Gap { oldest_seq } => panic!("unexpected gap at {oldest_seq}"),
    }
}
