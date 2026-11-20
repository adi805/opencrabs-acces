//! AC-010: presence — attaching a device shows up for the others, and a
//! device whose stream is gone stops being listed.
//!
//! Presence is derived from the registry rather than stored, so the test
//! asserts what `session/presence` would report: the device set of a session.

use crate::remote::registry::{Delivery, SessionRegistry};
use crate::remote::seq::Frame;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

fn frame(seq: u64) -> Arc<Frame> {
    Arc::new(Frame::new(seq, "text.delta", json!({})))
}

#[tokio::test]
async fn attach_and_timeout() {
    let session = Uuid::new_v4();
    let registry = SessionRegistry::new();
    let laptop = Uuid::new_v4();
    let phone = Uuid::new_v4();

    let _laptop_sub = registry.subscribe(session, laptop);
    assert_eq!(registry.devices(session), vec![laptop], "only the laptop");

    let phone_sub = registry.subscribe(session, phone);
    let mut devices = registry.devices(session);
    devices.sort();
    let mut expected = vec![laptop, phone];
    expected.sort();
    assert_eq!(devices, expected, "the phone is present to everyone");

    // The phone's stream dies. The registry only learns on the next publish,
    // which is the same signal a keepalive timeout produces.
    drop(phone_sub);
    let outcomes = registry.publish(session, frame(1));
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o, Delivery::Gone { .. })),
        "the dead stream is noticed"
    );
    assert_eq!(registry.devices(session), vec![laptop], "phone is gone");
    assert_eq!(registry.total_subscribers(), 1);
}

#[tokio::test]
async fn revoking_a_device_clears_its_presence_everywhere() {
    let registry = SessionRegistry::new();
    let device = Uuid::new_v4();
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();

    let _a = registry.subscribe(first, device);
    let _b = registry.subscribe(second, device);
    assert_eq!(registry.sessions_for_device(device).len(), 2);

    let cleared = registry.detach_device(device);
    assert_eq!(cleared.len(), 2, "both sessions dropped the device");
    assert!(registry.sessions_for_device(device).is_empty());
    assert_eq!(registry.total_subscribers(), 0);
}

#[tokio::test]
async fn presence_is_per_session_not_global() {
    let registry = SessionRegistry::new();
    let one = Uuid::new_v4();
    let two = Uuid::new_v4();
    let watcher = Uuid::new_v4();

    let _a = registry.subscribe(one, watcher);
    assert_eq!(registry.active_sessions(), 1);
    assert!(registry.devices(two).is_empty(), "no cross-session leak");
    assert_eq!(registry.devices(one), vec![watcher]);
}
