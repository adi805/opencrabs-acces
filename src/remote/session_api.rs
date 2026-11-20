//! JSON-RPC handlers for the remote session surface.
//!
//! Every handler takes the raw `params` value and answers a
//! [`JsonRpcResponse`], matching the existing `src/a2a/handler` style so the
//! dispatcher needs one match arm per method and nothing else changes.
//!
//! Validation is explicit rather than serde-derived: a missing field must
//! answer `VALIDATION_ERROR` naming the field, not a generic parse message,
//! because the PRD promises `details.field` in every validation failure.

use crate::a2a::types::{JsonRpcResponse, error_codes};
use crate::db::models::Message;
use crate::db::repository::{MessageRepository, SessionRepository};
use crate::remote::admission::ApprovalDecision;
use crate::remote::errors::RemoteError;
use crate::remote::relay::RelayState;
use crate::remote::scopes::SCOPE_SESSION_READ;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

/// Default page size for `session/history`.
pub const DEFAULT_HISTORY_LIMIT: usize = 50;
/// Upper bound on `session/history` page size.
pub const MAX_HISTORY_LIMIT: usize = 200;
/// Default page size for `session/list`.
pub const DEFAULT_LIST_LIMIT: usize = 50;
/// Upper bound on `session/list` page size.
pub const MAX_LIST_LIMIT: usize = 200;

/// A required parameter that could not be read.
fn need_str(params: &Value, field: &str) -> Result<String, RemoteError> {
    params
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| RemoteError::ValidationError {
            field: field.to_string(),
            reason: "required string".into(),
        })
}

/// A required uuid parameter.
fn need_uuid(params: &Value, field: &str) -> Result<Uuid, RemoteError> {
    let raw = need_str(params, field)?;
    Uuid::parse_str(&raw).map_err(|_| RemoteError::ValidationError {
        field: field.to_string(),
        reason: "not a uuid".into(),
    })
}

/// An optional integer parameter, clamped to `1..=max`.
fn opt_limit(
    params: &Value,
    field: &str,
    default: usize,
    max: usize,
) -> Result<usize, RemoteError> {
    match params.get(field) {
        None | Some(Value::Null) => Ok(default),
        Some(v) => {
            let n = v.as_u64().ok_or_else(|| RemoteError::ValidationError {
                field: field.to_string(),
                reason: "must be a non-negative integer".into(),
            })?;
            if n == 0 {
                return Err(RemoteError::ValidationError {
                    field: field.to_string(),
                    reason: "must be at least 1".into(),
                });
            }
            Ok((n as usize).min(max))
        }
    }
}

/// Turn a handler result into a JSON-RPC response.
fn respond(id: Value, result: Result<Value, RemoteError>) -> JsonRpcResponse {
    match result {
        Ok(v) => JsonRpcResponse::success(id, v),
        Err(e) => e.to_response(id),
    }
}

/// `session/list` — the owner's sessions with live turn state.
pub async fn handle_session_list(
    id: Value,
    params: Value,
    relay: Arc<RelayState>,
) -> JsonRpcResponse {
    let limit = match opt_limit(&params, "limit", DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT) {
        Ok(l) => l,
        Err(e) => return e.to_response(id),
    };
    // The cursor is the last `updated_at` the client saw, so paging is
    // stable even when a session is touched mid-page.
    let cursor = params
        .get("cursor")
        .and_then(Value::as_str)
        .map(str::to_string);

    let repo = SessionRepository::new(relay.service.pool());
    let options = crate::db::repository::SessionListOptions {
        include_archived: false,
        limit: Some(limit + 1),
        offset: 0,
        query: None,
        include_subagents: false,
    };
    let rows = match repo.list(options).await {
        Ok(r) => r,
        Err(e) => return RemoteError::internal(e.to_string()).to_response(id),
    };

    let mut sessions: Vec<Value> = Vec::with_capacity(limit.min(rows.len()));
    for row in rows.iter().take(limit) {
        let updated = row.updated_at.timestamp();
        if let Some(ref c) = cursor
            && let Ok(cursor_ts) = c.parse::<i64>()
            && updated >= cursor_ts
        {
            continue;
        }
        sessions.push(json!({
            "id": row.id,
            "title": row.title.clone().unwrap_or_default(),
            "updated_at": updated,
            "turn_state": relay.turn_state(row.id).as_str(),
        }));
    }
    let next_cursor = if rows.len() > limit {
        sessions.last().and_then(|s| s["updated_at"].as_i64())
    } else {
        None
    };
    respond(
        id,
        Ok(json!({
            "sessions": sessions,
            "next_cursor": next_cursor.map(|c| c.to_string()),
        })),
    )
}

/// `session/history` — page backwards through stored messages.
pub async fn handle_session_history(
    id: Value,
    params: Value,
    relay: Arc<RelayState>,
) -> JsonRpcResponse {
    let result = async {
        let session_id = need_uuid(&params, "session_id")?;
        let limit = opt_limit(&params, "limit", DEFAULT_HISTORY_LIMIT, MAX_HISTORY_LIMIT)?;
        ensure_session(&relay, session_id).await?;
        let before = match params.get("before_seq").and_then(Value::as_i64) {
            Some(n) if n > 0 => n as i32,
            Some(_) => {
                return Err(RemoteError::ValidationError {
                    field: "before_seq".into(),
                    reason: "must be at least 1".into(),
                });
            }
            None => i32::MAX,
        };
        let repo = MessageRepository::new(relay.service.pool());
        // One extra row tells us whether an older page exists.
        let mut rows = repo
            .find_recent_before_sequence(session_id, before, limit + 1)
            .await
            .map_err(|e| RemoteError::internal(e.to_string()))?;
        let has_more = rows.len() > limit;
        if has_more {
            rows.remove(0);
        }
        let messages: Vec<Value> = rows.iter().map(message_json).collect();
        Ok(json!({ "messages": messages, "has_more": has_more }))
    }
    .await;
    respond(id, result)
}

/// One stored message in the wire shape.
fn message_json(m: &Message) -> Value {
    json!({
        "seq": m.sequence,
        "role": m.role,
        "text": m.content,
        "created_at": m.created_at.timestamp(),
        "thinking": m.thinking,
    })
}

/// `session/send` — accept a user message and start or queue a turn.
pub async fn handle_session_send(
    id: Value,
    params: Value,
    relay: Arc<RelayState>,
) -> JsonRpcResponse {
    let result = async {
        let session_id = need_uuid(&params, "session_id")?;
        let text = need_str(&params, "text")?;
        let client_msg_id = need_uuid(&params, "client_msg_id")?;
        let outcome = relay.send(session_id, text, client_msg_id).await?;
        Ok(json!({
            "seq": outcome.seq,
            "queued": outcome.queued,
            "duplicate": outcome.duplicate,
        }))
    }
    .await;
    respond(id, result)
}

/// `session/interrupt` — cancel the running turn of a session.
pub async fn handle_session_interrupt(
    id: Value,
    params: Value,
    relay: Arc<RelayState>,
) -> JsonRpcResponse {
    let result = async {
        let session_id = need_uuid(&params, "session_id")?;
        let turn_id = need_uuid(&params, "turn_id")?;
        ensure_session(&relay, session_id).await?;
        if relay.interrupt(session_id, turn_id) {
            Ok(json!({ "accepted": true }))
        } else {
            Err(RemoteError::TurnBusy { turn_id })
        }
    }
    .await;
    respond(id, result)
}

/// `session/ack` — report the highest rendered seq.
pub async fn handle_session_ack(
    id: Value,
    params: Value,
    relay: Arc<RelayState>,
) -> JsonRpcResponse {
    let result = async {
        let session_id = need_uuid(&params, "session_id")?;
        let seq = params.get("seq").and_then(Value::as_u64).ok_or_else(|| {
            RemoteError::ValidationError {
                field: "seq".into(),
                reason: "required non-negative integer".into(),
            }
        })?;
        ensure_session(&relay, session_id).await?;
        relay.ack(session_id, seq);
        Ok(json!({ "ok": true }))
    }
    .await;
    respond(id, result)
}

/// `session/approve` — answer a pending tool approval from any device.
pub async fn handle_session_approve(
    id: Value,
    params: Value,
    relay: Arc<RelayState>,
    device_id: &str,
) -> JsonRpcResponse {
    let result = async {
        let session_id = need_uuid(&params, "session_id")?;
        let request_id = need_uuid(&params, "request_id")?;
        let raw = need_str(&params, "decision")?;
        let decision =
            ApprovalDecision::parse(&raw).ok_or_else(|| RemoteError::ValidationError {
                field: "decision".into(),
                reason: "must be approve, always or deny".into(),
            })?;
        ensure_session(&relay, session_id).await?;
        relay.approve(session_id, request_id, decision)?;
        Ok(json!({ "ok": true, "decided_by": device_id }))
    }
    .await;
    respond(id, result)
}

/// `session/presence` — which devices are attached to a session.
pub async fn handle_session_presence(
    id: Value,
    params: Value,
    relay: Arc<RelayState>,
) -> JsonRpcResponse {
    let result = async {
        let session_id = need_uuid(&params, "session_id")?;
        ensure_session(&relay, session_id).await?;
        let devices: Vec<Value> = relay
            .registry
            .subscribers(session_id)
            .into_iter()
            .map(|s| {
                json!({
                    "device_id": s.device_id,
                    "label": "",
                    "last_seen_at": crate::remote::now_secs(),
                })
            })
            .collect();
        Ok(json!({ "devices": devices }))
    }
    .await;
    respond(id, result)
}

/// `session/detach` — close one subscription without dropping the session.
///
/// Not in the PRD's endpoint table (the stream ending is the normal path),
/// but a client that reconnects needs a way to retire the old subscription
/// explicitly so presence does not show a phantom device.
pub async fn handle_session_detach(
    id: Value,
    params: Value,
    relay: Arc<RelayState>,
) -> JsonRpcResponse {
    let result = async {
        let session_id = need_uuid(&params, "session_id")?;
        let subscriber_id = need_uuid(&params, "subscriber_id")?;
        let removed = relay.registry.unsubscribe(session_id, subscriber_id);
        Ok(json!({ "detached": removed }))
    }
    .await;
    respond(id, result)
}

/// Confirm the session exists, answering `SESSION_NOT_FOUND` otherwise.
pub(crate) async fn ensure_session(
    relay: &RelayState,
    session_id: Uuid,
) -> Result<(), RemoteError> {
    let repo = SessionRepository::new(relay.service.pool());
    match repo.find_by_id(session_id).await {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(RemoteError::SessionNotFound { session_id }),
        Err(e) => Err(RemoteError::internal(e.to_string())),
    }
}

/// Answer a method the remote surface does not implement.
pub fn method_not_found(id: Value, method: &str) -> JsonRpcResponse {
    JsonRpcResponse::error(
        id,
        error_codes::METHOD_NOT_FOUND,
        format!("Method not found: {method}"),
    )
}

/// The scope a device must hold to read a session's stream.
pub const ATTACH_SCOPE: &str = SCOPE_SESSION_READ;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn need_str_names_the_missing_field() {
        let err = need_str(&json!({}), "session_id").unwrap_err();
        assert_eq!(err.code(), "VALIDATION_ERROR");
        assert_eq!(err.details()["field"], "session_id");
    }

    #[test]
    fn need_uuid_rejects_a_non_uuid() {
        let err = need_uuid(&json!({"session_id": "nope"}), "session_id").unwrap_err();
        assert_eq!(err.details()["reason"], "not a uuid");
    }

    #[test]
    fn opt_limit_clamps_and_rejects_zero() {
        assert_eq!(opt_limit(&json!({}), "limit", 50, 200).unwrap(), 50);
        assert_eq!(
            opt_limit(&json!({"limit": 5}), "limit", 50, 200).unwrap(),
            5
        );
        assert_eq!(
            opt_limit(&json!({"limit": 9999}), "limit", 50, 200).unwrap(),
            200
        );
        assert!(opt_limit(&json!({"limit": 0}), "limit", 50, 200).is_err());
        assert!(opt_limit(&json!({"limit": "x"}), "limit", 50, 200).is_err());
    }

    #[test]
    fn validation_errors_are_jsonrpc_shaped() {
        let resp = respond(
            json!(1),
            Err(RemoteError::SessionNotFound {
                session_id: Uuid::nil(),
            }),
        );
        let err = resp.error.expect("error");
        assert_eq!(err.data.unwrap()["code"], "SESSION_NOT_FOUND");
    }
}
