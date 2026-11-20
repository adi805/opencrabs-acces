//! AC-036: a provider failure reaches every attached client as the same
//! `RetryAttempt` then `ProviderSwitched` story the local GUI shows.
//!
//! The mapping is exercised through the sequence, not just the mapper, because
//! the AC is about order on the wire: a client that saw `provider.switched`
//! before `provider.retry` would draw the wrong banner.

use crate::brain::agent::service::ProgressEvent;
use crate::remote::events::map_progress;
use crate::remote::seq::{Replay, SessionSeq};

#[test]
fn provider_failure_forwarded() {
    let seq = SessionSeq::default();

    let retry = map_progress(&ProgressEvent::RetryAttempt {
        attempt: 1,
        max: 3,
        reason: "429 rate limited".to_string(),
    });
    let switched = map_progress(&ProgressEvent::ProviderSwitched {
        from_name: "primary".to_string(),
        from_model: "model-a".to_string(),
        to_name: "backup".to_string(),
        to_model: "model-b".to_string(),
        reason: "429 rate limited".to_string(),
    });

    assert_eq!(retry.kind, "provider.retry");
    assert_eq!(switched.kind, "provider.switched");
    assert_ne!(retry.kind, switched.kind, "two distinct banners");

    seq.publish(retry.kind, retry.payload)
        .expect("publish retry");
    seq.publish(switched.kind, switched.payload)
        .expect("publish switch");

    let frames = match seq.replay(0) {
        Replay::Frames(frames) => frames,
        Replay::Gap { oldest_seq } => panic!("unexpected gap at {oldest_seq}"),
    };
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].kind, "provider.retry", "retry comes first");
    assert_eq!(frames[0].payload["attempt"], serde_json::json!(1));
    assert_eq!(frames[0].payload["max"], serde_json::json!(3));
    assert_eq!(frames[1].kind, "provider.switched");
    assert_eq!(frames[1].payload["from_name"], serde_json::json!("primary"));
    assert_eq!(frames[1].payload["to_name"], serde_json::json!("backup"));
    assert_eq!(
        frames[1].payload["reason"],
        serde_json::json!("429 rate limited"),
        "the reason is forwarded verbatim so the client can show it"
    );
    assert!(frames[0].seq < frames[1].seq, "strictly increasing");
}

#[test]
fn streaming_text_keeps_the_turn_in_one_sequence() {
    let seq = SessionSeq::default();
    for chunk in ["Hel", "lo, ", "world"] {
        let mapped = map_progress(&ProgressEvent::StreamingChunk {
            text: chunk.to_string(),
        });
        seq.publish(mapped.kind, mapped.payload).expect("publish");
    }

    let frames = match seq.replay(0) {
        Replay::Frames(frames) => frames,
        Replay::Gap { oldest_seq } => panic!("unexpected gap at {oldest_seq}"),
    };
    let text: String = frames
        .iter()
        .map(|f| f.payload["text"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(text, "Hello, world", "chunks reassemble in seq order");
    let seqs: Vec<u64> = frames.iter().map(|f| f.seq).collect();
    assert_eq!(seqs, vec![1, 2, 3]);
}
