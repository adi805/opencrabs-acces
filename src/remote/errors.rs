//! Stable remote error vocabulary.
//!
//! The PRD (§8, Error Format) promises every failure arrives in one envelope:
//! a JSON-RPC 2.0 error object whose `data.code` is the stable STRING a client
//! branches on, with the numeric `rpc_code` mirrored beside it for transports
//! that need one. The existing gateway only carried numeric codes, so the
//! string table lives here and [`RemoteError::to_response`] builds both halves.
//!
//! Rules the table keeps:
//!
//! - `message` is human prose and never contains file content, keys or a
//!   message body.
//! - `details` carries the machine-readable remedy (which scope is missing,
//!   where replay begins, which field failed).
//! - `retryable` is true only where the same request may succeed later
//!   unchanged (rate limit, client offline, engine unreachable).
//!
//! Numeric range `-32010..=-32026` is reserved for this table so it can never
//! collide with the pre-existing `-32001..=-32004` set in `a2a::types`.

use crate::a2a::types::{JsonRpcError, JsonRpcResponse, error_codes};
use serde_json::{Value, json};
use uuid::Uuid;

/// `PATH_NAMESPACE_UNKNOWN`, as pinned by the PRD's worked example.
pub const RPC_PATH_NAMESPACE_UNKNOWN: i64 = -32010;
/// `PATH_OUTSIDE_GRANT`.
pub const RPC_PATH_OUTSIDE_GRANT: i64 = -32011;
/// `CLIENT_OFFLINE`.
pub const RPC_CLIENT_OFFLINE: i64 = -32012;
/// `CLIENT_NAMESPACE_NO_EXEC`.
pub const RPC_CLIENT_NAMESPACE_NO_EXEC: i64 = -32013;
/// `ARTIFACT_TOO_LARGE`.
pub const RPC_ARTIFACT_TOO_LARGE: i64 = -32014;
/// `ARTIFACT_HASH_MISMATCH`.
pub const RPC_ARTIFACT_HASH_MISMATCH: i64 = -32015;
/// `ARTIFACT_NOT_FOUND`.
pub const RPC_ARTIFACT_NOT_FOUND: i64 = -32016;
/// `DEVICE_NOT_FOUND`.
pub const RPC_DEVICE_NOT_FOUND: i64 = -32017;
/// `SESSION_NOT_FOUND`.
pub const RPC_SESSION_NOT_FOUND: i64 = -32018;
/// `TURN_BUSY`.
pub const RPC_TURN_BUSY: i64 = -32019;
/// `RESUME_GAP`.
pub const RPC_RESUME_GAP: i64 = -32020;
/// `TOKEN_EXPIRED`.
pub const RPC_TOKEN_EXPIRED: i64 = -32021;
/// `TOKEN_REVOKED`.
pub const RPC_TOKEN_REVOKED: i64 = -32022;
/// `PAIRING_CODE_INVALID`.
pub const RPC_PAIRING_CODE_INVALID: i64 = -32023;
/// `PAIRING_LOCKED`.
pub const RPC_PAIRING_LOCKED: i64 = -32024;
/// `RATE_LIMITED`.
pub const RPC_RATE_LIMITED: i64 = -32025;
/// `ENGINE_UNREACHABLE`.
pub const RPC_ENGINE_UNREACHABLE: i64 = -32026;

/// Every failure the remote surface can report.
#[derive(Debug, Clone, PartialEq)]
pub enum RemoteError {
    /// The submitted pairing code is unknown, expired or already consumed.
    PairingCodeInvalid { attempts_left: Option<u32> },
    /// Too many failed pairings from one source.
    PairingLocked { retry_after_ms: u64 },
    /// The device token's `expires_at` has passed.
    TokenExpired,
    /// The device was revoked, or its token hash is gone.
    TokenRevoked,
    /// `scope_for_method` returned a scope the token does not hold.
    ScopeDenied { missing_scope: String },
    /// Unknown, deleted, or another profile's session.
    SessionNotFound { session_id: Uuid },
    /// A turn runs and the queue is at its bound.
    TurnBusy { turn_id: Uuid },
    /// `resume_from` fell out of the ring buffer.
    ResumeGap { oldest_seq: u64 },
    /// The path lacks an `engine:` / `client:<device>:` prefix.
    PathNamespaceUnknown { input: String, available: Vec<String> },
    /// Canonicalisation escaped the granted root.
    PathOutsideGrant { grant_root: String },
    /// The named device has no live connection.
    ClientOffline { device_id: String },
    /// A tool tried to execute inside a `client:` namespace.
    ClientNamespaceNoExec { path: String },
    /// Body or file exceeds `OPENCRABS_ARTIFACT_MAX_BYTES`.
    ArtifactTooLarge { max_bytes: u64 },
    /// Streamed sha256 differs from the announced one.
    ArtifactHashMismatch { expected: String, actual: String },
    /// Unknown artifact id, or pruned by retention.
    ArtifactNotFound { id: Uuid },
    /// `device/revoke` named an id this profile does not have.
    DeviceNotFound { device_id: String },
    /// No route, tunnel or health probe answered (client side).
    EngineUnreachable,
    /// The engine or proxy throttles the caller.
    RateLimited { retry_after_ms: u64 },
    /// An invariant broke; `request_id` correlates to the log line.
    Internal { request_id: String },
    /// A required param is missing, mistyped or out of range.
    ValidationError { field: String, reason: String },
}

impl RemoteError {
    /// The stable string code a client branches on.
    pub fn code(&self) -> &'static str {
        match self {
            Self::PairingCodeInvalid { .. } => "PAIRING_CODE_INVALID",
            Self::PairingLocked { .. } => "PAIRING_LOCKED",
            Self::TokenExpired => "TOKEN_EXPIRED",
            Self::TokenRevoked => "TOKEN_REVOKED",
            Self::ScopeDenied { .. } => "SCOPE_DENIED",
            Self::SessionNotFound { .. } => "SESSION_NOT_FOUND",
            Self::TurnBusy { .. } => "TURN_BUSY",
            Self::ResumeGap { .. } => "RESUME_GAP",
            Self::PathNamespaceUnknown { .. } => "PATH_NAMESPACE_UNKNOWN",
            Self::PathOutsideGrant { .. } => "PATH_OUTSIDE_GRANT",
            Self::ClientOffline { .. } => "CLIENT_OFFLINE",
            Self::ClientNamespaceNoExec { .. } => "CLIENT_NAMESPACE_NO_EXEC",
            Self::ArtifactTooLarge { .. } => "ARTIFACT_TOO_LARGE",
            Self::ArtifactHashMismatch { .. } => "ARTIFACT_HASH_MISMATCH",
            Self::ArtifactNotFound { .. } => "ARTIFACT_NOT_FOUND",
            Self::DeviceNotFound { .. } => "DEVICE_NOT_FOUND",
            Self::EngineUnreachable => "ENGINE_UNREACHABLE",
            Self::RateLimited { .. } => "RATE_LIMITED",
            Self::Internal { .. } => "INTERNAL",
            Self::ValidationError { .. } => "VALIDATION_ERROR",
        }
    }

    /// Numeric JSON-RPC code mirrored into `data.rpc_code`.
    pub fn rpc_code(&self) -> i64 {
        match self {
            Self::PairingCodeInvalid { .. } => RPC_PAIRING_CODE_INVALID,
            Self::PairingLocked { .. } => RPC_PAIRING_LOCKED,
            Self::TokenExpired => RPC_TOKEN_EXPIRED,
            Self::TokenRevoked => RPC_TOKEN_REVOKED,
            Self::ScopeDenied { .. } => error_codes::INSUFFICIENT_SCOPE,
            Self::SessionNotFound { .. } => RPC_SESSION_NOT_FOUND,
            Self::TurnBusy { .. } => RPC_TURN_BUSY,
            Self::ResumeGap { .. } => RPC_RESUME_GAP,
            Self::PathNamespaceUnknown { .. } => RPC_PATH_NAMESPACE_UNKNOWN,
            Self::PathOutsideGrant { .. } => RPC_PATH_OUTSIDE_GRANT,
            Self::ClientOffline { .. } => RPC_CLIENT_OFFLINE,
            Self::ClientNamespaceNoExec { .. } => RPC_CLIENT_NAMESPACE_NO_EXEC,
            Self::ArtifactTooLarge { .. } => RPC_ARTIFACT_TOO_LARGE,
            Self::ArtifactHashMismatch { .. } => RPC_ARTIFACT_HASH_MISMATCH,
            Self::ArtifactNotFound { .. } => RPC_ARTIFACT_NOT_FOUND,
            Self::DeviceNotFound { .. } => RPC_DEVICE_NOT_FOUND,
            Self::EngineUnreachable => RPC_ENGINE_UNREACHABLE,
            Self::RateLimited { .. } => RPC_RATE_LIMITED,
            Self::Internal { .. } => error_codes::INTERNAL_ERROR,
            Self::ValidationError { .. } => error_codes::INVALID_PARAMS,
        }
    }

    /// HTTP status a plain-HTTP route answers with.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::PairingCodeInvalid { .. } | Self::TokenExpired | Self::TokenRevoked => 401,
            Self::ScopeDenied { .. } | Self::PathOutsideGrant { .. } => 403,
            Self::SessionNotFound { .. }
            | Self::ArtifactNotFound { .. }
            | Self::DeviceNotFound { .. } => 404,
            Self::TurnBusy { .. } | Self::ResumeGap { .. } => 409,
            Self::ArtifactTooLarge { .. } => 413,
            Self::ArtifactHashMismatch { .. } => 422,
            Self::PairingLocked { .. } | Self::RateLimited { .. } => 429,
            Self::ClientOffline { .. } | Self::EngineUnreachable => 503,
            Self::PathNamespaceUnknown { .. }
            | Self::ClientNamespaceNoExec { .. }
            | Self::ValidationError { .. } => 400,
            Self::Internal { .. } => 500,
        }
    }

    /// True only when retrying the identical request may succeed later.
    pub fn retryable(&self) -> bool {
        matches!(
            self,
            Self::ClientOffline { .. }
                | Self::EngineUnreachable
                | Self::RateLimited { .. }
                | Self::PairingLocked { .. }
        )
    }

    /// Human prose. Never carries content, keys or a message body.
    pub fn message(&self) -> &'static str {
        match self {
            Self::PairingCodeInvalid { .. } => "Pairing code not recognised",
            Self::PairingLocked { .. } => "Too many pairing attempts",
            Self::TokenExpired => "Device token expired",
            Self::TokenRevoked => "Device token revoked",
            Self::ScopeDenied { .. } => "Token lacks the required scope",
            Self::SessionNotFound { .. } => "Session not found",
            Self::TurnBusy { .. } => "A turn is already running",
            Self::ResumeGap { .. } => "Requested event no longer buffered",
            Self::PathNamespaceUnknown { .. } => "Path namespace not recognised",
            Self::PathOutsideGrant { .. } => "Path escapes the granted root",
            Self::ClientOffline { .. } => "Target client is not attached",
            Self::ClientNamespaceNoExec { .. } => "Tool execution is engine-only",
            Self::ArtifactTooLarge { .. } => "Artifact exceeds the size cap",
            Self::ArtifactHashMismatch { .. } => "Artifact hash does not match",
            Self::ArtifactNotFound { .. } => "Artifact not found",
            Self::DeviceNotFound { .. } => "Device not found",
            Self::EngineUnreachable => "Engine did not answer",
            Self::RateLimited { .. } => "Request rate exceeded",
            Self::Internal { .. } => "Internal engine error",
            Self::ValidationError { .. } => "Request failed validation",
        }
    }

    /// Machine-readable remedy.
    pub fn details(&self) -> Value {
        match self {
            Self::PairingCodeInvalid { attempts_left } => json!({ "attempts_left": attempts_left }),
            Self::PairingLocked { retry_after_ms } | Self::RateLimited { retry_after_ms } => {
                json!({ "retry_after_ms": retry_after_ms })
            }
            Self::TokenExpired | Self::TokenRevoked | Self::EngineUnreachable => json!({}),
            Self::ScopeDenied { missing_scope } => json!({ "missing_scope": missing_scope }),
            Self::SessionNotFound { session_id } => json!({ "session_id": session_id }),
            Self::TurnBusy { turn_id } => json!({ "turn_id": turn_id }),
            Self::ResumeGap { oldest_seq } => json!({ "oldest_seq": oldest_seq }),
            Self::PathNamespaceUnknown { input, available } => {
                json!({ "input": input, "available": available })
            }
            Self::PathOutsideGrant { grant_root } => json!({ "grant_root": grant_root }),
            Self::ClientOffline { device_id } => json!({ "device_id": device_id }),
            Self::ClientNamespaceNoExec { path } => json!({ "path": path }),
            Self::ArtifactTooLarge { max_bytes } => json!({ "max_bytes": max_bytes }),
            Self::ArtifactHashMismatch { expected, actual } => {
                json!({ "expected": expected, "actual": actual })
            }
            Self::ArtifactNotFound { id } => json!({ "id": id }),
            Self::DeviceNotFound { device_id } => json!({ "device_id": device_id }),
            Self::Internal { request_id } => json!({ "request_id": request_id }),
            Self::ValidationError { field, reason } => {
                json!({ "field": field, "reason": reason })
            }
        }
    }

    /// The complete JSON-RPC error envelope the PRD specifies.
    pub fn to_response(&self, id: Value) -> JsonRpcResponse {
        let mut data = self.details();
        if let Some(obj) = data.as_object_mut() {
            obj.insert("code".to_string(), json!(self.code()));
            obj.insert("rpc_code".to_string(), json!(self.rpc_code()));
            obj.insert("http_status".to_string(), json!(self.http_status()));
            obj.insert("retryable".to_string(), json!(self.retryable()));
        }
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(JsonRpcError {
                code: self.rpc_code(),
                message: self.message().to_string(),
                data: Some(data),
            }),
            id,
        }
    }

    /// Convenience for handlers that map a `Result<T, RemoteError>`.
    pub fn internal(request_id: impl Into<String>) -> Self {
        Self::Internal {
            request_id: request_id.into(),
        }
    }
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for RemoteError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_errors() -> Vec<RemoteError> {
        vec![
            RemoteError::PairingCodeInvalid {
                attempts_left: Some(3),
            },
            RemoteError::PairingLocked {
                retry_after_ms: 900_000,
            },
            RemoteError::TokenExpired,
            RemoteError::TokenRevoked,
            RemoteError::ScopeDenied {
                missing_scope: "session:send".into(),
            },
            RemoteError::SessionNotFound {
                session_id: Uuid::nil(),
            },
            RemoteError::TurnBusy {
                turn_id: Uuid::nil(),
            },
            RemoteError::ResumeGap { oldest_seq: 41 },
            RemoteError::PathNamespaceUnknown {
                input: "C:\\notes.md".into(),
                available: vec!["engine:".into()],
            },
            RemoteError::PathOutsideGrant {
                grant_root: "D:\\share".into(),
            },
            RemoteError::ClientOffline {
                device_id: "dev-1".into(),
            },
            RemoteError::ClientNamespaceNoExec {
                path: "client:B:/x.exe".into(),
            },
            RemoteError::ArtifactTooLarge {
                max_bytes: 64 * 1024 * 1024,
            },
            RemoteError::ArtifactHashMismatch {
                expected: "aa".into(),
                actual: "bb".into(),
            },
            RemoteError::ArtifactNotFound { id: Uuid::nil() },
            RemoteError::DeviceNotFound {
                device_id: "dev-2".into(),
            },
            RemoteError::EngineUnreachable,
            RemoteError::RateLimited {
                retry_after_ms: 1_000,
            },
            RemoteError::Internal {
                request_id: "9f1c3b0a".into(),
            },
            RemoteError::ValidationError {
                field: "session_id".into(),
                reason: "not a uuid".into(),
            },
        ]
    }

    #[test]
    fn every_error_has_a_unique_string_code() {
        let mut codes: Vec<&str> = sample_errors().iter().map(|e| e.code()).collect();
        let count = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), count, "duplicate string code in the table");
    }

    #[test]
    fn numeric_codes_stay_in_the_reserved_range_or_reuse_known_ones() {
        for e in sample_errors() {
            let code = e.rpc_code();
            let in_reserved = (-32026..=-32010).contains(&code);
            let reused = matches!(
                code,
                error_codes::INSUFFICIENT_SCOPE | error_codes::INVALID_PARAMS | error_codes::INTERNAL_ERROR
            );
            assert!(in_reserved || reused, "{} uses code {code}", e.code());
        }
    }

    #[test]
    fn envelope_carries_string_code_numeric_mirror_and_status() {
        let err = RemoteError::ResumeGap { oldest_seq: 7 };
        let resp = err.to_response(json!(5));
        assert_eq!(resp.jsonrpc, "2.0");
        assert!(resp.result.is_none());
        let e = resp.error.expect("error object");
        assert_eq!(e.code, RPC_RESUME_GAP);
        let data = e.data.expect("data");
        assert_eq!(data["code"], "RESUME_GAP");
        assert_eq!(data["rpc_code"], RPC_RESUME_GAP);
        assert_eq!(data["http_status"], 409);
        assert_eq!(data["retryable"], false);
        assert_eq!(data["oldest_seq"], 7);
    }

    #[test]
    fn messages_never_echo_request_content() {
        let err = RemoteError::ValidationError {
            field: "text".into(),
            reason: "must not be empty".into(),
        };
        assert!(!err.message().contains("must not be empty"));
        assert_eq!(err.message(), "Request failed validation");
    }

    #[test]
    fn retryable_is_limited_to_transient_failures() {
        assert!(RemoteError::ClientOffline {
            device_id: "d".into()
        }
        .retryable());
        assert!(RemoteError::RateLimited {
            retry_after_ms: 1
        }
        .retryable());
        assert!(!RemoteError::SessionNotFound {
            session_id: Uuid::nil()
        }
        .retryable());
        assert!(!RemoteError::ScopeDenied {
            missing_scope: "fs:client".into()
        }
        .retryable());
    }

    #[test]
    fn prd_worked_example_matches_the_builder() {
        // PRD §8 shows PATH_NAMESPACE_UNKNOWN with rpc_code -32010 and 400.
        let err = RemoteError::PathNamespaceUnknown {
            input: "C:\\Users\\acer\\notes.md".into(),
            available: vec!["engine:".into(), "client:B:".into()],
        };
        let resp = err.to_response(json!(7));
        let e = resp.error.unwrap();
        assert_eq!(e.code, -32010);
        assert_eq!(e.message, "Path namespace not recognised");
        assert_eq!(e.data.unwrap()["http_status"], 400);
    }
}
