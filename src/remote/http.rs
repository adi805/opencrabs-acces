//! Route one remote method to its handler.
//!
//! Kept out of `a2a::server` so the gateway file stays about transport while
//! this file owns the method→handler table. Returns `None` for a method the
//! classic A2A surface owns, so the caller falls through to the existing
//! dispatcher unchanged.

use crate::a2a::types::JsonRpcResponse;
use crate::remote::{device_api, relay::RelayState, session_api};
use serde_json::Value;
use std::sync::Arc;

/// Methods this module answers. `session/attach` is absent on purpose: it
/// answers an SSE stream rather than a JSON body, so the gateway handles it.
pub const REMOTE_METHODS: &[&str] = &[
    "session/list",
    "session/history",
    "session/send",
    "session/interrupt",
    "session/ack",
    "session/approve",
    "session/presence",
    "session/detach",
    "device/list",
    "device/revoke",
    "device/self",
];

/// True when `method` belongs to the remote surface.
pub fn is_remote_method(method: &str) -> bool {
    REMOTE_METHODS.contains(&method)
}

/// Answer a remote method, or `None` when it is not one.
pub async fn dispatch(
    relay: Arc<RelayState>,
    id: Value,
    method: &str,
    params: Value,
    device_id: Option<&str>,
) -> Option<JsonRpcResponse> {
    let device = device_id.unwrap_or("");
    let response = match method {
        "session/list" => session_api::handle_session_list(id, params, relay).await,
        "session/history" => session_api::handle_session_history(id, params, relay).await,
        "session/send" => session_api::handle_session_send(id, params, relay).await,
        "session/interrupt" => session_api::handle_session_interrupt(id, params, relay).await,
        "session/ack" => session_api::handle_session_ack(id, params, relay).await,
        "session/approve" => session_api::handle_session_approve(id, params, relay, device).await,
        "session/presence" => session_api::handle_session_presence(id, params, relay).await,
        "session/detach" => session_api::handle_session_detach(id, params, relay).await,
        "device/list" | "device/revoke" | "device/self" => {
            device_api::dispatch_device(id, method, params, relay, device)
        }
        _ => return None,
    };
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::scopes::scope_for_method;

    #[test]
    fn every_remote_method_is_routed_or_streamed() {
        for m in REMOTE_METHODS {
            assert!(is_remote_method(m), "{m} not routed");
        }
        // session/attach is deliberately outside this table.
        assert!(!is_remote_method("session/attach"));
        assert!(scope_for_method("session/attach").is_some());
    }

    #[test]
    fn classic_methods_fall_through() {
        for m in ["message/send", "tasks/get", "session/notify", "nope"] {
            assert!(!is_remote_method(m), "{m} must reach the old dispatcher");
        }
    }

    #[test]
    fn every_session_method_carries_a_scope() {
        for m in REMOTE_METHODS.iter().filter(|m| m.starts_with("session/")) {
            assert!(scope_for_method(m).is_some(), "{m} has no scope");
        }
    }

    #[test]
    fn every_device_method_carries_a_scope() {
        for m in ["device/list", "device/revoke"] {
            assert!(scope_for_method(m).is_some(), "{m} has no scope");
        }
    }
}
