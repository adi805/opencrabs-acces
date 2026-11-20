//! Capability scopes for remote A2A access.
//!
//! Nine scopes, plain wire strings, stored verbatim on pairing codes and
//! session tokens:
//!
//! | Scope               | Grants                                                        |
//! |---------------------|---------------------------------------------------------------|
//! | `a2a:read`          | `tasks/get`, `session/notify-status`                           |
//! | `a2a:send`          | `message/send`, `message/stream`, `tasks/cancel`, `session/notify` |
//! | `session:list`      | `session/list`                                                 |
//! | `session:read`      | `session/history`, `session/attach`, `session/ack`, `session/presence` |
//! | `session:send`      | `session/send`                                                 |
//! | `session:control`   | `session/interrupt`, `session/approve`                         |
//! | `fs:client`         | `fs/list`, `fs/read`, `fs/write`                               |
//! | `device:admin`      | `device/list`, `device/revoke`                                 |
//! | `artifact:transfer` | `GET /a2a/v1/artifact/{id}`, `POST /a2a/v1/artifact`           |
//!
//! Rules:
//! - Scopes only ever narrow: a pairing exchange picks a subset of
//!   [`ALL_SCOPES`], never adds to what the code carried.
//! - The config `[a2a].api_key` bearer implicitly holds every scope
//!   (full access, backward compatible with existing callers).
//! - Flat strings, exact membership: no wildcards, no hierarchy, no
//!   implication graph. A scope check is one string comparison.
//! - Unknown JSON-RPC methods get no scope gate here; the dispatcher
//!   rejects them with `MethodNotFound` regardless of credentials.
//! - The `a2a:*` pair predates the session surface and keeps its exact
//!   meaning: a token minted before this table grew stays exactly as
//!   powerful as it was, never silently wider.

/// Read-only scope: fetch task state, check notification delivery.
pub const SCOPE_READ: &str = "a2a:read";
/// Operate scope: send/stream messages, cancel tasks, push notifications.
pub const SCOPE_SEND: &str = "a2a:send";
/// Enumerate the owner's sessions without reading their contents.
pub const SCOPE_SESSION_LIST: &str = "session:list";
/// Read a session's stored history, attach to its live stream, acknowledge
/// frames, and see which devices are attached to it.
pub const SCOPE_SESSION_READ: &str = "session:read";
/// Submit user messages into a session, starting or queueing a turn.
pub const SCOPE_SESSION_SEND: &str = "session:send";
/// Steer a running turn: interrupt it, or answer a pending tool approval.
pub const SCOPE_SESSION_CONTROL: &str = "session:control";
/// Serve a client's granted folders to the engine's VFS proxy.
pub const SCOPE_FS_CLIENT: &str = "fs:client";
/// Administer paired devices: list them, revoke them.
pub const SCOPE_DEVICE_ADMIN: &str = "device:admin";
/// Move artifact bytes in either direction over the plain HTTP routes.
pub const SCOPE_ARTIFACT_TRANSFER: &str = "artifact:transfer";

/// Every scope the system knows. Mint-time validation rejects anything
/// else so stored state never contains typos that silently grant nothing.
pub const ALL_SCOPES: &[&str] = &[
    SCOPE_READ,
    SCOPE_SEND,
    SCOPE_SESSION_LIST,
    SCOPE_SESSION_READ,
    SCOPE_SESSION_SEND,
    SCOPE_SESSION_CONTROL,
    SCOPE_FS_CLIENT,
    SCOPE_DEVICE_ADMIN,
    SCOPE_ARTIFACT_TRANSFER,
];

/// Scopes a fresh pairing code carries when the caller names none: read and
/// send over the classic A2A surface only. The session surface is opt-in,
/// so a device paired by an older client cannot suddenly drive a turn.
pub const DEFAULT_PAIRING_SCOPES: &[&str] = &[SCOPE_READ, SCOPE_SEND];

/// The scope required by one JSON-RPC method, or `None` when the method
/// needs no scope gate (unknown methods: the dispatcher rejects them).
///
/// Keep in sync with the method surface in `src/a2a/handler/dispatch.rs`,
/// the SSE path in `src/a2a/server.rs`, and the session handlers in
/// `src/remote/session_api.rs`. The exhaustiveness test below is the guard.
///
/// The artifact routes are plain HTTP rather than JSON-RPC methods; they
/// gate on [`SCOPE_ARTIFACT_TRANSFER`] directly at the route handler, which
/// is why no method string maps to it here.
pub fn scope_for_method(method: &str) -> Option<&'static str> {
    match method {
        "tasks/get" | "session/notify-status" => Some(SCOPE_READ),
        "message/send" | "message/stream" | "tasks/cancel" | "session/notify" => Some(SCOPE_SEND),
        "session/list" => Some(SCOPE_SESSION_LIST),
        "session/history" | "session/attach" | "session/ack" | "session/presence" => {
            Some(SCOPE_SESSION_READ)
        }
        "session/send" => Some(SCOPE_SESSION_SEND),
        "session/interrupt" | "session/approve" => Some(SCOPE_SESSION_CONTROL),
        "fs/list" | "fs/read" | "fs/write" => Some(SCOPE_FS_CLIENT),
        "device/list" | "device/revoke" => Some(SCOPE_DEVICE_ADMIN),
        _ => None,
    }
}

/// Is `s` a scope this system knows? Case-sensitive, exact match.
pub fn is_known_scope(s: &str) -> bool {
    ALL_SCOPES.contains(&s)
}

/// Does a session's granted scope list satisfy `required`?
pub fn allows(granted: &[String], required: &str) -> bool {
    granted.iter().map(String::as_str).any(|g| g == required)
}

/// Does a session hold at least one of `required`? Used by routes that
/// accept several scopes (`/a2a/routes` takes any scope at all).
pub fn allows_any(granted: &[String], required: &[&str]) -> bool {
    granted
        .iter()
        .map(String::as_str)
        .any(|g| required.contains(&g))
}

/// Drop unknown scopes from a caller-supplied list, preserving order and
/// removing duplicates. Used where a bad scope should narrow the token
/// rather than fail the whole pairing exchange.
pub fn sanitize(scopes: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(scopes.len());
    for s in scopes {
        if is_known_scope(s) && !out.iter().any(|k| k == s) {
            out.push(s.clone());
        }
    }
    out
}

/// The default grant, as owned strings ready to store on a code.
pub fn default_pairing_scopes() -> Vec<String> {
    DEFAULT_PAIRING_SCOPES
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}
