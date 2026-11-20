//! Engine-side VFS proxy: `engine:` and `client:<device>:` namespaces.
//!
//! Two filesystems, one path grammar. A path the model writes is either
//! `engine:/abs/path` — the engine's own disk, the default — or
//! `client:<device>:/rel/path`, a folder a paired device granted to this
//! engine. Anything else is [`RemoteError::PathNamespaceUnknown`] carrying the
//! namespaces that DO exist, so the model can correct itself in one turn
//! instead of three (FR-013, AC-017).
//!
//! The client leg is request/reply, not a shared filesystem (FR-012):
//!
//! 1. `fs/list` / `fs/read` / `fs/write` resolves the namespace. `engine:`
//!    is served locally; `client:` is never touched locally, which is what
//!    makes AC-016 ("the engine's temp dir is unchanged") a structural
//!    property rather than a promise.
//! 2. For a client path the engine registers a pending request, publishes
//!    `fs.request {request_id, op, path}` on the device's session stream, and
//!    waits. SSE is engine→client only, so the answer comes back as a plain
//!    RPC: `fs/reply {request_id, bytes, sha256}` over `POST /a2a/v1`.
//! 3. Silence for [`FS_REPLY_TIMEOUT`] is [`RemoteError::ClientOffline`], not
//!    a hang. A reply whose sha256 does not match its own bytes is
//!    [`RemoteError::ArtifactHashMismatch`].
//!
//! Code never executes inside a `client:` namespace: [`ensure_exec_allowed`]
//! answers [`RemoteError::ClientNamespaceNoExec`] for it, because the folder
//! belongs to another machine and "run this binary there" is not a file
//! operation.

use crate::a2a::types::JsonRpcResponse;
use crate::remote::artifact::configured_max_bytes;
use crate::remote::errors::RemoteError;
use crate::remote::relay::{RelayState, device_key};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;
use uuid::Uuid;

/// Prefix of the engine's own filesystem. The default when a model omits one
/// is NOT applied here: an unprefixed path is an error the model must see.
pub const ENGINE_PREFIX: &str = "engine:";
/// Prefix of a device-granted folder: `client:<device_id>:`.
pub const CLIENT_PREFIX: &str = "client:";
/// How long a device has to answer `fs.request` before it is `CLIENT_OFFLINE`.
pub const FS_REPLY_TIMEOUT: Duration = Duration::from_secs(30);
/// Event kind published on the session stream to reach a device.
pub const KIND_FS_REQUEST: &str = "fs.request";

/// Which filesystem a resolved path lives on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Namespace {
    /// The engine's own disk.
    Engine { path: PathBuf },
    /// A folder granted by `device_id`; `path` is relative to that grant.
    Client { device_id: String, path: String },
}

impl Namespace {
    /// True for the `client:` arm, which is read/write only and never local.
    pub fn is_client(&self) -> bool {
        matches!(self, Self::Client { .. })
    }

    /// The namespace label a client sees, with a trailing colon.
    pub fn label(&self) -> String {
        match self {
            Self::Engine { .. } => ENGINE_PREFIX.to_string(),
            Self::Client { device_id, .. } => format!("{CLIENT_PREFIX}{device_id}:"),
        }
    }

    /// The device that owns this namespace, when it is a client one.
    pub fn client_device(&self) -> Option<&str> {
        match self {
            Self::Client { device_id, .. } => Some(device_id.as_str()),
            Self::Engine { .. } => None,
        }
    }
}

/// The namespaces a path may name right now, in the order they are offered.
pub fn available_namespaces(devices: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(devices.len() + 1);
    out.push(ENGINE_PREFIX.to_string());
    for d in devices {
        out.push(format!("{CLIENT_PREFIX}{d}:"));
    }
    out
}

/// Resolve a model-written path to the filesystem it belongs to.
///
/// `devices` are the paired device ids; they are only used to build the
/// `available` list of the error, never to authorise a namespace — a path
/// naming an unknown device still resolves to [`Namespace::Client`] and the
/// device leg answers `CLIENT_OFFLINE` when nothing is attached.
pub fn resolve_path(input: &str, devices: &[String]) -> Result<Namespace, RemoteError> {
    let trimmed = input.trim();
    if let Some(rest) = trimmed.strip_prefix(ENGINE_PREFIX) {
        let path = rest.trim();
        if path.is_empty() {
            return Err(RemoteError::ValidationError {
                field: "path".into(),
                reason: "engine: names no file".into(),
            });
        }
        return Ok(Namespace::Engine {
            path: PathBuf::from(path),
        });
    }
    if let Some(rest) = trimmed.strip_prefix(CLIENT_PREFIX) {
        // `client:<device>:<path>`; the device id is one colon-separated
        // segment, so the path may carry colons (a Windows drive inside the
        // grant) without confusing the split.
        let (device_id, path) = match rest.split_once(':') {
            Some((d, p)) => (d.trim(), p.trim()),
            None => {
                return Err(RemoteError::ValidationError {
                    field: "path".into(),
                    reason: "client: needs a device id and a path".into(),
                });
            }
        };
        if device_id.is_empty() {
            return Err(RemoteError::ValidationError {
                field: "path".into(),
                reason: "client: names no device".into(),
            });
        }
        return Ok(Namespace::Client {
            device_id: device_id.to_string(),
            path: path.to_string(),
        });
    }
    Err(RemoteError::PathNamespaceUnknown {
        input: input.to_string(),
        available: available_namespaces(devices),
    })
}

/// Normalise the path part of a `client:` namespace to something relative.
///
/// The device interprets it inside its own grant root, so a leading `/` is
/// cosmetic (`client:B:/notes/x.md` → `notes/x.md`). A `..` segment, a root
/// component or a Windows prefix is an escape attempt and answers
/// [`RemoteError::PathOutsideGrant`] — the grant root is the whole contract,
/// and no path may climb out of it.
pub fn client_relative_path(path: &str, root_label: &str) -> Result<String, RemoteError> {
    let trimmed = path.trim().trim_start_matches(['/', '\\']);
    if trimmed.is_empty() {
        return Err(RemoteError::ValidationError {
            field: "path".into(),
            reason: "names no file inside the grant".into(),
        });
    }
    let outside = Path::new(trimmed).components().any(|c| {
        matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    });
    if outside {
        return Err(RemoteError::PathOutsideGrant {
            grant_root: root_label.to_string(),
        });
    }
    Ok(trimmed.replace('\\', "/"))
}

/// Refuse tool execution inside a client namespace.
///
/// A `client:` folder is another machine's disk. Reading and writing it is a
/// file operation the device consents to; running a binary there is not in
/// the protocol at all, so the refusal is structural.
pub fn ensure_exec_allowed(ns: &Namespace) -> Result<(), RemoteError> {
    match ns {
        Namespace::Client { device_id, path } => Err(RemoteError::ClientNamespaceNoExec {
            path: format!("{CLIENT_PREFIX}{device_id}:{path}"),
        }),
        Namespace::Engine { .. } => Ok(()),
    }
}

/// One directory entry as `fs/list` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub size: u64,
    /// Unix seconds; 0 when the platform cannot report it.
    pub mtime: u64,
    pub is_dir: bool,
}

/// The operation a `fs.request` asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsOp {
    List,
    Read,
    Write,
}

impl FsOp {
    /// Wire name used in `fs.request`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// A device's answer to one `fs.request`.
#[derive(Debug, Clone, PartialEq)]
pub struct FsReply {
    pub request_id: Uuid,
    pub bytes: Option<Vec<u8>>,
    pub sha256: Option<String>,
    pub entries: Option<Vec<DirEntry>>,
    /// The device's own refusal, passed through as a validation failure.
    pub error: Option<String>,
}

/// Pending `fs.request` correlation.
///
/// Holds one sender per in-flight request. A reply is delivered by
/// `request_id`, which is why the reply leg can be a plain RPC from a device
/// that is not the one the engine is talking to on any other channel.
#[derive(Debug)]
pub struct FsProxy {
    pending: Mutex<HashMap<Uuid, oneshot::Sender<FsReply>>>,
    timeout: Duration,
}

impl FsProxy {
    /// Proxy with the contract's 30 s reply deadline.
    pub fn new() -> Self {
        Self::with_timeout(FS_REPLY_TIMEOUT)
    }

    /// Proxy with an explicit deadline (tests use a short one so a silent
    /// device is proven silent without waiting 30 s).
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            timeout,
        }
    }

    /// Register a request and get the receiver its reply arrives on.
    ///
    /// A duplicate id is refused rather than silently replacing the first
    /// receiver: two waiters on one id would let a reply resolve the wrong
    /// caller.
    pub fn begin(&self, request_id: Uuid) -> Result<oneshot::Receiver<FsReply>, RemoteError> {
        let (tx, rx) = oneshot::channel();
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending.contains_key(&request_id) {
            return Err(RemoteError::ValidationError {
                field: "request_id".into(),
                reason: "already in flight".into(),
            });
        }
        pending.insert(request_id, tx);
        Ok(rx)
    }

    /// Deliver a device's reply. False when the id is unknown or the waiter
    /// is gone, which the `fs/reply` handler reports as a validation failure.
    pub fn deliver(&self, reply: FsReply) -> bool {
        let sender = {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            pending.remove(&reply.request_id)
        };
        match sender {
            Some(tx) => tx.send(reply).is_ok(),
            None => false,
        }
    }

    /// Forget a request (timeout, or the caller gave up).
    pub fn cancel(&self, request_id: Uuid) -> bool {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&request_id)
            .is_some()
    }

    /// Requests still waiting for a reply.
    pub fn pending_count(&self) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Wait for the reply, or answer `CLIENT_OFFLINE` at the deadline.
    pub async fn await_reply(
        &self,
        request_id: Uuid,
        device_id: &str,
        rx: oneshot::Receiver<FsReply>,
    ) -> Result<FsReply, RemoteError> {
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(reply)) => Ok(reply),
            // A dropped sender means the pending entry went away under us
            // (cancel, or the process is shutting down). Either way the device
            // did not answer, which is exactly what CLIENT_OFFLINE means.
            Ok(Err(_)) | Err(_) => {
                self.cancel(request_id);
                Err(RemoteError::ClientOffline {
                    device_id: device_id.to_string(),
                })
            }
        }
    }
}

impl Default for FsProxy {
    fn default() -> Self {
        Self::new()
    }
}

/// Lowercase hex sha256 — the one hash spelling the whole surface uses.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// List a directory on the engine's own filesystem.
pub fn list_engine(path: &Path) -> Result<Vec<DirEntry>, RemoteError> {
    let read = std::fs::read_dir(path).map_err(|e| io_error(e, path))?;
    let mut entries: Vec<DirEntry> = Vec::new();
    for item in read {
        let item = item.map_err(|e| io_error(e, path))?;
        let meta = item.metadata().map_err(|e| io_error(e, &item.path()))?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        entries.push(DirEntry {
            name: item.file_name().to_string_lossy().into_owned(),
            size: meta.len(),
            mtime,
            is_dir: meta.is_dir(),
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

/// Read bytes from the engine's own filesystem.
///
/// Returns `(bytes, truncated)`. `truncated` is true when `length` cut the
/// read short, so a client can page without guessing.
pub fn read_engine(
    path: &Path,
    offset: u64,
    length: Option<u64>,
    max_bytes: u64,
) -> Result<(Vec<u8>, bool), RemoteError> {
    let meta = std::fs::metadata(path).map_err(|e| io_error(e, path))?;
    if meta.len() > max_bytes {
        return Err(RemoteError::ArtifactTooLarge { max_bytes });
    }
    let all = std::fs::read(path).map_err(|e| io_error(e, path))?;
    let start = (offset as usize).min(all.len());
    let end = match length {
        Some(n) => (start + n as usize).min(all.len()),
        None => all.len(),
    };
    let truncated = end < all.len();
    Ok((all[start..end].to_vec(), truncated))
}

/// Write bytes to the engine's own filesystem, creating parent directories.
pub fn write_engine(path: &Path, bytes: &[u8]) -> Result<(), RemoteError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| io_error(e, parent))?;
    }
    std::fs::write(path, bytes).map_err(|e| io_error(e, path))
}

/// One filesystem failure as the stable envelope. Never carries file content.
fn io_error(err: std::io::Error, path: &Path) -> RemoteError {
    RemoteError::internal(format!("{}: {err}", path.display()))
}

/// base64 for the wire's `bytes_base64` fields.
pub(crate) fn encode_bytes(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Inverse of [`encode_bytes`].
pub(crate) fn decode_bytes(text: &str) -> Result<Vec<u8>, RemoteError> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| RemoteError::ValidationError {
            field: "bytes_base64".into(),
            reason: "not valid base64".into(),
        })
}

/// The paired device ids, for the `available` list and namespace checks.
fn paired_devices(relay: &RelayState) -> Vec<String> {
    relay
        .pairing
        .list_sessions()
        .map(|rows| rows.into_iter().map(|r| r.id).collect())
        .unwrap_or_default()
}

/// The session a device is attached to, which is where `fs.request` is
/// published. No attachment means the request has nowhere to go.
fn device_session(relay: &RelayState, device_id: &str) -> Option<Uuid> {
    relay
        .registry
        .sessions_for_device(device_key(device_id))
        .into_iter()
        .next()
}

/// Send one `fs.request` and wait for the device's `fs/reply`.
pub(crate) async fn client_op(
    relay: &Arc<RelayState>,
    device_id: &str,
    op: FsOp,
    path: &str,
    extra: Value,
) -> Result<FsReply, RemoteError> {
    let session_id = device_session(relay, device_id).ok_or_else(|| RemoteError::ClientOffline {
        device_id: device_id.to_string(),
    })?;
    let request_id = Uuid::new_v4();
    let rx = relay.fs.begin(request_id)?;
    let published = relay.publish(
        session_id,
        KIND_FS_REQUEST,
        json!({
            "request_id": request_id,
            "op": op.as_str(),
            "path": path,
            "device_id": device_id,
            "params": extra,
        }),
    );
    if published.is_none() {
        relay.fs.cancel(request_id);
        return Err(RemoteError::internal("fs.request frame too large"));
    }
    let reply = relay.fs.await_reply(request_id, device_id, rx).await?;
    match reply.error.as_deref() {
        Some(reason) => Err(RemoteError::ValidationError {
            field: "fs/reply".into(),
            reason: reason.to_string(),
        }),
        None => Ok(reply),
    }
}

/// A required string parameter, naming the field when it is absent.
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

/// Turn a handler result into a JSON-RPC response.
fn respond(id: Value, result: Result<Value, RemoteError>) -> JsonRpcResponse {
    match result {
        Ok(v) => JsonRpcResponse::success(id, v),
        Err(e) => e.to_response(id),
    }
}

/// `fs/list` — entries of a folder, engine-local or served by a device.
pub async fn handle_fs_list(id: Value, params: Value, relay: Arc<RelayState>) -> JsonRpcResponse {
    let result = async {
        let raw = need_str(&params, "path")?;
        let devices = paired_devices(&relay);
        match resolve_path(&raw, &devices)? {
            Namespace::Engine { path } => {
                let entries = list_engine(&path)?;
                Ok(json!({ "namespace": ENGINE_PREFIX, "entries": entries }))
            }
            Namespace::Client { device_id, path } => {
                let label = format!("{CLIENT_PREFIX}{device_id}:");
                let rel = client_relative_path(&path, &label)?;
                let reply = client_op(&relay, &device_id, FsOp::List, &rel, json!({})).await?;
                Ok(json!({
                    "namespace": label,
                    "entries": reply.entries.unwrap_or_default(),
                }))
            }
        }
    }
    .await;
    respond(id, result)
}

/// `fs/read` — bytes from a grant (or the engine), with offset paging.
///
/// A device's bytes are only accepted when they hash to the sha256 the device
/// announced with them; anything else is `ARTIFACT_HASH_MISMATCH` rather than
/// silently serving corrupt content.
pub async fn handle_fs_read(id: Value, params: Value, relay: Arc<RelayState>) -> JsonRpcResponse {
    let result = async {
        let raw = need_str(&params, "path")?;
        let offset = params.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let length = params.get("length").and_then(Value::as_u64);
        let devices = paired_devices(&relay);
        match resolve_path(&raw, &devices)? {
            Namespace::Engine { path } => {
                let (bytes, truncated) =
                    read_engine(&path, offset, length, configured_max_bytes())?;
                Ok(json!({
                    "namespace": ENGINE_PREFIX,
                    "bytes_base64": encode_bytes(&bytes),
                    "sha256": sha256_hex(&bytes),
                    "truncated": truncated,
                }))
            }
            Namespace::Client { device_id, path } => {
                let label = format!("{CLIENT_PREFIX}{device_id}:");
                let rel = client_relative_path(&path, &label)?;
                let extra = json!({ "offset": offset, "length": length });
                let reply = client_op(&relay, &device_id, FsOp::Read, &rel, extra).await?;
                let bytes = reply.bytes.unwrap_or_default();
                let actual = sha256_hex(&bytes);
                match reply.sha256 {
                    Some(expected) if !expected.eq_ignore_ascii_case(&actual) => {
                        return Err(RemoteError::ArtifactHashMismatch { expected, actual });
                    }
                    _ => {}
                }
                Ok(json!({
                    "namespace": label,
                    "bytes_base64": encode_bytes(&bytes),
                    "sha256": actual,
                    "truncated": false,
                }))
            }
        }
    }
    .await;
    respond(id, result)
}

/// `fs/write` — bytes into a grant, hash-checked before they land.
pub async fn handle_fs_write(id: Value, params: Value, relay: Arc<RelayState>) -> JsonRpcResponse {
    let result = async {
        let raw = need_str(&params, "path")?;
        let encoded = need_str(&params, "bytes_base64")?;
        let announced = need_str(&params, "sha256")?;
        let bytes = decode_bytes(&encoded)?;
        let max_bytes = configured_max_bytes();
        if bytes.len() as u64 > max_bytes {
            return Err(RemoteError::ArtifactTooLarge { max_bytes });
        }
        let actual = sha256_hex(&bytes);
        if !announced.eq_ignore_ascii_case(&actual) {
            return Err(RemoteError::ArtifactHashMismatch {
                expected: announced,
                actual,
            });
        }
        let devices = paired_devices(&relay);
        match resolve_path(&raw, &devices)? {
            Namespace::Engine { path } => {
                write_engine(&path, &bytes)?;
                Ok(json!({
                    "namespace": ENGINE_PREFIX,
                    "bytes_written": bytes.len(),
                    "sha256": actual,
                }))
            }
            Namespace::Client { device_id, path } => {
                let label = format!("{CLIENT_PREFIX}{device_id}:");
                let rel = client_relative_path(&path, &label)?;
                let extra = json!({ "bytes_base64": encoded, "sha256": actual });
                let reply = client_op(&relay, &device_id, FsOp::Write, &rel, extra).await?;
                let written = reply
                    .bytes
                    .as_ref()
                    .map(|b| b.len())
                    .unwrap_or(bytes.len());
                Ok(json!({
                    "namespace": label,
                    "bytes_written": written,
                    "sha256": reply.sha256.unwrap_or(actual),
                }))
            }
        }
    }
    .await;
    respond(id, result)
}

/// `fs/reply` — the client's answer leg for one `fs.request`.
///
/// A reply for an id this engine is not waiting on is a validation failure,
/// never a silent success: the client must learn its answer arrived too late
/// (the request timed out) instead of assuming the write landed.
pub fn handle_fs_reply(id: Value, params: Value, relay: Arc<RelayState>) -> JsonRpcResponse {
    let result = (|| {
        let request_id = params
            .get("request_id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| RemoteError::ValidationError {
                field: "request_id".into(),
                reason: "required uuid".into(),
            })?;
        let bytes = match params.get("bytes_base64").and_then(Value::as_str) {
            Some(text) => Some(decode_bytes(text)?),
            None => None,
        };
        let entries = match params.get("entries") {
            Some(Value::Null) | None => None,
            Some(v) => Some(serde_json::from_value::<Vec<DirEntry>>(v.clone()).map_err(|_| {
                RemoteError::ValidationError {
                    field: "entries".into(),
                    reason: "must be an array of entries".into(),
                }
            })?),
        };
        let reply = FsReply {
            request_id,
            bytes,
            sha256: params
                .get("sha256")
                .and_then(Value::as_str)
                .map(str::to_string),
            entries,
            error: params
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_string),
        };
        if !relay.fs.deliver(reply) {
            return Err(RemoteError::ValidationError {
                field: "request_id".into(),
                reason: "unknown or already answered".into(),
            });
        }
        Ok(json!({ "accepted": true }))
    })();
    respond(id, result)
}

/// Route one `fs/*` method.
pub async fn dispatch_fs(
    id: Value,
    method: &str,
    params: Value,
    relay: Arc<RelayState>,
) -> JsonRpcResponse {
    match method {
        "fs/list" => handle_fs_list(id, params, relay).await,
        "fs/read" => handle_fs_read(id, params, relay).await,
        "fs/write" => handle_fs_write(id, params, relay).await,
        "fs/reply" => handle_fs_reply(id, params, relay),
        other => crate::remote::session_api::method_not_found(id, other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn devices() -> Vec<String> {
        vec!["B".to_string(), "C".to_string()]
    }

    #[test]
    fn engine_paths_resolve_to_the_engine_namespace() {
        let ns = resolve_path("engine:/tmp/notes.md", &devices()).expect("resolves");
        assert_eq!(
            ns,
            Namespace::Engine {
                path: PathBuf::from("/tmp/notes.md")
            }
        );
        assert!(!ns.is_client());
    }

    #[test]
    fn client_paths_keep_the_device_and_drop_the_root() {
        let ns = resolve_path("client:B:/notes/report.md", &devices()).expect("resolves");
        assert_eq!(
            ns,
            Namespace::Client {
                device_id: "B".into(),
                path: "/notes/report.md".into()
            }
        );
        assert_eq!(ns.label(), "client:B:");
        assert_eq!(
            client_relative_path("/notes/report.md", "client:B:").unwrap(),
            "notes/report.md"
        );
    }

    #[test]
    fn a_bare_path_names_no_namespace() {
        let err = resolve_path("C:\\Users\\acer\\notes.md", &devices()).unwrap_err();
        assert_eq!(err.code(), "PATH_NAMESPACE_UNKNOWN");
        assert_eq!(
            err.details()["available"],
            json!(["engine:", "client:B:", "client:C:"])
        );
    }

    #[test]
    fn climbing_out_of_the_grant_is_refused() {
        let err = client_relative_path("../../etc/passwd", "client:B:").unwrap_err();
        assert_eq!(err.code(), "PATH_OUTSIDE_GRANT");
        assert_eq!(err.details()["grant_root"], "client:B:");
    }

    #[test]
    fn exec_is_refused_inside_a_client_namespace() {
        let ns = Namespace::Client {
            device_id: "B".into(),
            path: "/x.exe".into(),
        };
        assert_eq!(
            ensure_exec_allowed(&ns).unwrap_err().code(),
            "CLIENT_NAMESPACE_NO_EXEC"
        );
        assert!(
            ensure_exec_allowed(&Namespace::Engine {
                path: PathBuf::from("/x")
            })
            .is_ok()
        );
    }

    #[tokio::test]
    async fn a_silent_device_times_out_instead_of_hanging() {
        let proxy = FsProxy::with_timeout(Duration::from_millis(20));
        let id = Uuid::new_v4();
        let rx = proxy.begin(id).expect("begin");
        let err = proxy.await_reply(id, "B", rx).await.unwrap_err();
        assert_eq!(err.code(), "CLIENT_OFFLINE");
        assert!(err.retryable());
        assert_eq!(proxy.pending_count(), 0, "the wait was cleaned up");
    }

    #[tokio::test]
    async fn a_reply_reaches_the_waiter_and_leaves_nothing_pending() {
        let proxy = Arc::new(FsProxy::new());
        let id = Uuid::new_v4();
        let rx = proxy.begin(id).expect("begin");
        let sender = Arc::clone(&proxy);
        tokio::spawn(async move {
            sender.deliver(FsReply {
                request_id: id,
                bytes: Some(b"hello".to_vec()),
                sha256: Some(sha256_hex(b"hello")),
                entries: None,
                error: None,
            });
        });
        let reply = proxy.await_reply(id, "B", rx).await.expect("reply");
        assert_eq!(reply.bytes.unwrap(), b"hello");
        assert_eq!(proxy.pending_count(), 0);
    }

    #[test]
    fn sha256_is_lowercase_hex_of_the_bytes() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
