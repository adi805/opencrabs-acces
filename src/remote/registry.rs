//! Subscriber registry: one engine event fans out to every attached client.
//!
//! A session is watched by zero or more devices. Each subscriber gets a
//! bounded channel; publishing never blocks the agent's turn. A subscriber
//! that stops draining its channel is dropped after
//! [`MAX_CONSECUTIVE_MISSES`] refused sends and reported as
//! [`Delivery::Lagging`], so the session API can tell that client to
//! reattach with `resume_from` and catch up from the sequence buffer
//! instead of silently falling behind forever.
//!
//! Frames are `Arc<Frame>` so one event costs one allocation regardless of
//! fanout.

use crate::remote::seq::Frame;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Channel depth per subscriber. Deep enough to absorb a burst of streaming
/// deltas between two client polls, shallow enough that a dead client is
/// detected in well under a second of streaming.
pub const DEFAULT_SUBSCRIBER_BUFFER: usize = 256;

/// Consecutive refused sends tolerated before a subscriber is dropped.
/// `try_send` refuses once the channel is full, so this counts a client
/// that is not reading at all rather than one briefly behind.
pub const MAX_CONSECUTIVE_MISSES: u64 = 32;

/// One attached device's receive half. Dropping it detaches the device.
pub struct Subscription {
    /// Unique per attach call, so one device may attach twice (two panes).
    pub subscriber_id: Uuid,
    /// The device the subscription belongs to (pairing identity).
    pub device_id: Uuid,
    /// Frames in publish order.
    pub rx: mpsc::Receiver<Arc<Frame>>,
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("subscriber_id", &self.subscriber_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

/// What happened to one subscriber during a publish.
#[derive(Debug, Clone, PartialEq)]
pub enum Delivery {
    /// Queued for this subscriber.
    Delivered,
    /// Refused enough times in a row that the subscriber was detached.
    Lagging {
        subscriber_id: Uuid,
        device_id: Uuid,
        skipped: u64,
    },
    /// The receiver is gone; the subscriber was detached.
    Gone { subscriber_id: Uuid },
}

/// A subscriber as reported to `session/presence`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriberInfo {
    pub subscriber_id: Uuid,
    pub device_id: Uuid,
}

struct Entry {
    info: SubscriberInfo,
    tx: mpsc::Sender<Arc<Frame>>,
    misses: u64,
}

/// Session-id → attached subscribers.
#[derive(Debug, Default)]
pub struct SessionRegistry {
    sessions: Mutex<HashMap<Uuid, Vec<Entry>>>,
    buffer: usize,
    max_misses: u64,
}

impl SessionRegistry {
    /// Registry with default buffer depth and miss tolerance.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_SUBSCRIBER_BUFFER, MAX_CONSECUTIVE_MISSES)
    }

    /// Registry with explicit limits (tests and tuning).
    pub fn with_limits(buffer: usize, max_misses: u64) -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            buffer: buffer.max(1),
            max_misses: max_misses.max(1),
        }
    }

    /// Attach a device to a session. The returned receiver yields frames in
    /// publish order; dropping it detaches.
    pub fn subscribe(&self, session_id: Uuid, device_id: Uuid) -> Subscription {
        let (tx, rx) = mpsc::channel(self.buffer);
        let subscriber_id = Uuid::new_v4();
        let mut map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        map.entry(session_id).or_default().push(Entry {
            info: SubscriberInfo {
                subscriber_id,
                device_id,
            },
            tx,
            misses: 0,
        });
        Subscription {
            subscriber_id,
            device_id,
            rx,
        }
    }

    /// Detach one subscriber explicitly (client called `session/detach`, or
    /// its HTTP stream ended).
    pub fn unsubscribe(&self, session_id: Uuid, subscriber_id: Uuid) -> bool {
        let mut map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let Some(list) = map.get_mut(&session_id) else {
            return false;
        };
        let before = list.len();
        list.retain(|e| e.info.subscriber_id != subscriber_id);
        let removed = list.len() != before;
        if list.is_empty() {
            map.remove(&session_id);
        }
        removed
    }

    /// Fan one frame out to every subscriber of `session_id`.
    ///
    /// Never blocks. Returns one [`Delivery`] per subscriber that was not
    /// simply delivered, so the caller can surface lag or detach.
    pub fn publish(&self, session_id: Uuid, frame: Arc<Frame>) -> Vec<Delivery> {
        let mut map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let Some(list) = map.get_mut(&session_id) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut drop_ids: Vec<Uuid> = Vec::new();
        for entry in list.iter_mut() {
            match entry.tx.try_send(frame.clone()) {
                Ok(()) => {
                    entry.misses = 0;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    entry.misses += 1;
                    if entry.misses >= self.max_misses {
                        out.push(Delivery::Lagging {
                            subscriber_id: entry.info.subscriber_id,
                            device_id: entry.info.device_id,
                            skipped: entry.misses,
                        });
                        drop_ids.push(entry.info.subscriber_id);
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    out.push(Delivery::Gone {
                        subscriber_id: entry.info.subscriber_id,
                    });
                    drop_ids.push(entry.info.subscriber_id);
                }
            }
        }
        if !drop_ids.is_empty() {
            list.retain(|e| !drop_ids.contains(&e.info.subscriber_id));
            if list.is_empty() {
                map.remove(&session_id);
            }
        }
        out
    }

    /// Subscribers currently attached to a session, for `session/presence`.
    pub fn subscribers(&self, session_id: Uuid) -> Vec<SubscriberInfo> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&session_id)
            .map(|l| l.iter().map(|e| e.info).collect())
            .unwrap_or_default()
    }

    /// Distinct device ids attached to a session.
    pub fn devices(&self, session_id: Uuid) -> Vec<Uuid> {
        let mut ids: Vec<Uuid> = self
            .subscribers(session_id)
            .into_iter()
            .map(|s| s.device_id)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Sessions a device is attached to (used to reap a revoked device).
    pub fn sessions_for_device(&self, device_id: Uuid) -> Vec<Uuid> {
        let map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        map.iter()
            .filter(|(_, list)| list.iter().any(|e| e.info.device_id == device_id))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Detach every subscriber of a device and return the session ids it was
    /// attached to. Revocation calls this so a revoked token stops receiving
    /// frames immediately rather than at its next request.
    pub fn detach_device(&self, device_id: Uuid) -> Vec<Uuid> {
        let mut map = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let mut touched = Vec::new();
        for (session_id, list) in map.iter_mut() {
            let before = list.len();
            list.retain(|e| e.info.device_id != device_id);
            if list.len() != before {
                touched.push(*session_id);
            }
        }
        map.retain(|_, list| !list.is_empty());
        touched
    }

    /// Drop every subscriber of a session (session deleted, or restart sweep).
    pub fn drop_session(&self, session_id: Uuid) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&session_id);
    }

    /// Total attached subscribers across sessions.
    pub fn total_subscribers(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|l| l.len())
            .sum()
    }

    /// Sessions with at least one subscriber.
    pub fn active_sessions(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn frame(seq: u64) -> Arc<Frame> {
        Arc::new(Frame::new(seq, "text.delta", json!({"seq": seq})))
    }

    #[tokio::test]
    async fn one_frame_reaches_every_subscriber() {
        let reg = SessionRegistry::new();
        let session = Uuid::new_v4();
        let mut a = reg.subscribe(session, Uuid::new_v4());
        let mut b = reg.subscribe(session, Uuid::new_v4());
        assert_eq!(reg.subscribers(session).len(), 2);
        assert!(reg.publish(session, frame(1)).is_empty());

        assert_eq!(a.rx.recv().await.unwrap().seq, 1);
        assert_eq!(b.rx.recv().await.unwrap().seq, 1);
    }

    #[tokio::test]
    async fn unsubscribe_stops_delivery() {
        let reg = SessionRegistry::new();
        let session = Uuid::new_v4();
        let mut a = reg.subscribe(session, Uuid::new_v4());
        let b = reg.subscribe(session, Uuid::new_v4());
        assert!(reg.unsubscribe(session, b.subscriber_id));
        assert!(!reg.unsubscribe(session, b.subscriber_id));
        assert!(reg.publish(session, frame(1)).is_empty());
        assert_eq!(a.rx.recv().await.unwrap().seq, 1);
        assert!(a.rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_client_that_never_reads_is_detached_as_lagging() {
        let reg = SessionRegistry::with_limits(1, 2);
        let session = Uuid::new_v4();
        let device = Uuid::new_v4();
        let _stuck = reg.subscribe(session, device);

        // First publish fills the one-slot channel.
        assert!(reg.publish(session, frame(1)).is_empty());
        // Miss 1.
        assert!(reg.publish(session, frame(2)).is_empty());
        // Miss 2 reaches the tolerance: reported and dropped.
        let out = reg.publish(session, frame(3));
        assert!(matches!(
            out.as_slice(),
            [Delivery::Lagging { device_id, skipped: 2, .. }] if *device_id == device
        ));
        assert!(reg.subscribers(session).is_empty());
    }

    #[tokio::test]
    async fn dropping_the_receiver_reports_gone() {
        let reg = SessionRegistry::with_limits(1, 4);
        let session = Uuid::new_v4();
        let sub = reg.subscribe(session, Uuid::new_v4());
        drop(sub);
        let out = reg.publish(session, frame(1));
        assert!(matches!(out.as_slice(), [Delivery::Gone { .. }]));
        assert!(reg.subscribers(session).is_empty());
    }

    #[tokio::test]
    async fn revoking_a_device_detaches_all_its_sessions() {
        let reg = SessionRegistry::new();
        let device = Uuid::new_v4();
        let s1 = Uuid::new_v4();
        let s2 = Uuid::new_v4();
        let _a = reg.subscribe(s1, device);
        let _b = reg.subscribe(s2, device);
        let _other = reg.subscribe(s1, Uuid::new_v4());

        let mut touched = reg.detach_device(device);
        touched.sort_unstable();
        let mut expected = vec![s1, s2];
        expected.sort_unstable();
        assert_eq!(touched, expected);
        assert_eq!(reg.subscribers(s1).len(), 1, "the other device stays");
        assert!(reg.subscribers(s2).is_empty());
        assert_eq!(reg.total_subscribers(), 1);
    }

    #[tokio::test]
    async fn publish_to_an_unwatched_session_is_a_no_op() {
        let reg = SessionRegistry::new();
        assert!(reg.publish(Uuid::new_v4(), frame(1)).is_empty());
        assert_eq!(reg.active_sessions(), 0);
    }

    #[tokio::test]
    async fn two_attachments_of_one_device_are_counted_separately() {
        let reg = SessionRegistry::new();
        let session = Uuid::new_v4();
        let device = Uuid::new_v4();
        let _a = reg.subscribe(session, device);
        let _b = reg.subscribe(session, device);
        assert_eq!(reg.subscribers(session).len(), 2);
        assert_eq!(reg.devices(session), vec![device]);
        assert_eq!(reg.sessions_for_device(device), vec![session]);
    }
}
