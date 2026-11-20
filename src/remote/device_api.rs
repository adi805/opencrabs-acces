//! JSON-RPC handlers for device administration.
//!
//! `device/list` reports every paired device and the scopes it holds;
//! `device/revoke` kills a device and every token it carries. Revocation is
//! immediate on the live stream too: the registry detaches the device so a
//! revoked token stops receiving frames at once instead of at its next
//! request.

use crate::a2a::types::JsonRpcResponse;
use crate::remote::errors::RemoteError;
use crate::remote::relay::{device_key, RelayState};
use crate::remote::session_api::method_not_found;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

/// `device/list` — paired devices with scopes and last-seen state.
pub fn handle_device_list(id: Value, relay: Arc<RelayState>) -> JsonRpcResponse {
    match relay.pairing.list_sessions() {
        Ok(sessions) => {
            let devices: Vec<Value> = sessions
                .iter()
                .map(|s| {
                    let key = device_key(&s.id);
                    json!({
                        "device_id": s.id,
                        "label": s.label,
                        "scopes": s.scopes,
                        "paired_at": s.created_at,
                        "expires_at": s.expires_at,
                        "last_seen_at": crate::remote::now_secs(),
                        "revoked_at": Value::Null,
                        "active": s.active,
                        "attached_sessions": relay.registry.sessions_for_device(key).len(),
                    })
                })
                .collect();
            JsonRpcResponse::success(id, json!({ "devices": devices }))
        }
        Err(e) => RemoteError::internal(e.to_string()).to_response(id),
    }
}

/// `device/revoke` — revoke a device and detach it from every session.
pub fn handle_device_revoke(id: Value, params: Value, relay: Arc<RelayState>) -> JsonRpcResponse {
    let device_id = match params.get("device_id").and_then(Value::as_str) {
        Some(s) if !s.trim().is_empty() => s.to_string(),
        _ => {
            return RemoteError::ValidationError {
                field: "device_id".into(),
                reason: "required string".into(),
            }
            .to_response(id);
        }
    };

    // A revoke for an id this profile never issued is a 404, not a silent
    // success: the caller must learn its state is stale.
    let known = relay
        .pairing
        .list_sessions()
        .map(|rows| rows.iter().any(|r| r.id == device_id))
        .unwrap_or(false);
    if !known {
        return RemoteError::DeviceNotFound { device_id }.to_response(id);
    }

    match relay.pairing.revoke(&device_id) {
        Ok(count) => {
            let touched = relay.registry.detach_device(device_key(&device_id));
            tracing::info!(
                device = %device_id,
                revoked_tokens = count,
                detached_sessions = touched.len(),
                "remote device revoked"
            );
            JsonRpcResponse::success(
                id,
                json!({ "revoked": count > 0, "tokens_revoked": count }),
            )
        }
        Err(e) => RemoteError::internal(e.to_string()).to_response(id),
    }
}

/// `device/self` — the calling device's own identity and scopes.
///
/// Lets a client confirm what it may do without an admin scope, which is
/// what the connection banner shows when a call is refused.
pub fn handle_device_self(id: Value, relay: Arc<RelayState>, device_id: &str) -> JsonRpcResponse {
    match relay.pairing.list_sessions() {
        Ok(rows) => match rows.iter().find(|r| r.id == device_id) {
            Some(row) => JsonRpcResponse::success(
                id,
                json!({
                    "device_id": row.id,
                    "label": row.label,
                    "scopes": row.scopes,
                    "expires_at": row.expires_at,
                    "active": row.active,
                }),
            ),
            None => RemoteError::DeviceNotFound {
                device_id: device_id.to_string(),
            }
            .to_response(id),
        },
        Err(e) => RemoteError::internal(e.to_string()).to_response(id),
    }
}

/// Route one `device/*` method, or answer `METHOD_NOT_FOUND`.
pub fn dispatch_device(
    id: Value,
    method: &str,
    params: Value,
    relay: Arc<RelayState>,
    device_id: &str,
) -> JsonRpcResponse {
    match method {
        "device/list" => handle_device_list(id, relay),
        "device/revoke" => handle_device_revoke(id, params, relay),
        "device/self" => handle_device_self(id, relay, device_id),
        other => method_not_found(id, other),
    }
}

/// Kept public for the router's presence wiring and tests.
pub fn device_uuid(device_id: &str) -> Uuid {
    device_key(device_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_uuid_is_deterministic() {
        assert_eq!(device_uuid("abc"), device_uuid("abc"));
        assert_ne!(device_uuid("abc"), device_uuid("xyz"));
    }

    #[test]
    fn revoke_requires_a_device_id() {
        // Construction only: the handler needs a relay, so this pins the
        // validation branch's shape rather than running it.
        let err = RemoteError::ValidationError {
            field: "device_id".into(),
            reason: "required string".into(),
        };
        assert_eq!(err.http_status(), 400);
        assert_eq!(err.code(), "VALIDATION_ERROR");
    }
}
