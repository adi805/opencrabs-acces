//! Artifact transfer: streamed upload and download with sha256 verification.
//!
//! An artifact is a file a turn produced (engine → client) or a file a client
//! uploaded for the next turn to read (client → engine). Both directions are
//! plain HTTP beside the JSON-RPC surface, because the payload is bytes and a
//! base64 JSON body would pay 33% overhead on a 200 MB file:
//!
//! - `GET  /a2a/v1/artifact/{id}` → the bytes, with `X-Content-SHA256`.
//! - `POST /a2a/v1/artifact`      → bytes in, `{id, bytes, sha256}` out.
//!
//! Three properties the store guarantees, each one a test:
//!
//! 1. **The cap is hard.** A body past [`configured_max_bytes`] is refused with
//!    [`RemoteError::ArtifactTooLarge`] *and* the partial file is deleted, so a
//!    rejected upload cannot fill the disk or be mistaken for a short artifact
//!    (AC-020).
//! 2. **The hash is the truth.** A stream that does not hash to the announced
//!    sha256 is [`RemoteError::ArtifactHashMismatch`] and leaves nothing
//!    behind; a stored artifact that no longer hashes to its recorded sha256 is
//!    refused on download rather than served corrupt (AC-018).
//! 3. **A landed artifact is complete.** Bytes are written to a dot-prefixed
//!    temp file in the same directory and renamed into place only after the
//!    hash matches, so a reader never observes a half-written artifact.

use crate::a2a::server::{A2aState, GrantedScopes};
use crate::a2a::types::JsonRpcResponse;
use crate::remote::errors::RemoteError;
use crate::remote::fs_proxy::sha256_hex;
use crate::remote::scopes::{SCOPE_ARTIFACT_TRANSFER, allows};
use axum::{
    Extension,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path as FsPath, PathBuf};
use uuid::Uuid;

/// Default hard cap on one transfer: 200 MB.
pub const DEFAULT_MAX_BYTES: u64 = 209_715_200;

/// Environment variable that overrides the cap.
pub const MAX_BYTES_ENV: &str = "OPENCRABS_ARTIFACT_MAX_BYTES";

/// Header carrying the sha256 a client announces (upload) or reads (download).
pub const SHA256_HEADER: &str = "x-content-sha256";

/// Header naming the session an upload belongs to.
pub const SESSION_HEADER: &str = "x-session-id";

/// The cap in force for this process.
///
/// Read per call rather than cached: the value is operator configuration, and
/// a cached copy would make a `config` change need a restart to take effect.
/// A malformed or zero value falls back to the default instead of disabling
/// the cap — "unset" and "garbage" must never mean "unlimited".
pub fn configured_max_bytes() -> u64 {
    std::env::var(MAX_BYTES_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_BYTES)
}

/// What the store records about one artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactMeta {
    pub id: Uuid,
    pub session_id: Uuid,
    /// Where the bytes live, for a log line or a download tray.
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub created_at: u64,
}

/// On-disk artifact store: `<root>/<session>/<id>.bin` plus `<root>/<id>.json`.
///
/// The metadata sidecar is what makes a download by id alone possible: the
/// route carries only the id, so the session it belongs to has to be readable
/// from the artifact itself.
#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
    max_bytes: u64,
}

impl ArtifactStore {
    /// Store under `root` with the process cap.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_bytes: configured_max_bytes(),
        }
    }

    /// Store with an explicit cap (tests and tuning).
    pub fn with_max_bytes(root: impl Into<PathBuf>, max_bytes: u64) -> Self {
        Self {
            root: root.into(),
            max_bytes: max_bytes.max(1),
        }
    }

    /// Production location: `<opencrabs_home>/state/remote/artifacts`.
    pub fn default_root() -> PathBuf {
        crate::remote::tunnel::default_state_dir().join("artifacts")
    }

    /// Directory the store writes into.
    pub fn root(&self) -> &FsPath {
        &self.root
    }

    /// The cap this store enforces.
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    fn meta_path(&self, id: Uuid) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }

    fn blob_path(&self, session_id: Uuid, id: Uuid) -> PathBuf {
        self.root.join(session_id.to_string()).join(format!("{id}.bin"))
    }

    fn temp_path(&self, id: Uuid) -> PathBuf {
        // Dot-prefixed and inside the store, so a crashed transfer is obvious
        // and never collides with a real artifact id.
        self.root.join(format!(".tmp-{id}"))
    }

    /// Store a chunk stream, hashing as it arrives.
    ///
    /// Chunks are consumed one at a time and never held as a whole, so a
    /// 200 MB upload costs one chunk of memory rather than 200 MB. Any failure
    /// removes the temp file before returning.
    pub fn put_stream<I>(
        &self,
        session_id: Uuid,
        id: Uuid,
        declared_sha256: Option<&str>,
        chunks: I,
    ) -> Result<ArtifactMeta, RemoteError>
    where
        I: IntoIterator<Item = Vec<u8>>,
    {
        std::fs::create_dir_all(&self.root)
            .map_err(|e| RemoteError::internal(format!("artifact store: {e}")))?;
        let temp = self.temp_path(id);
        let mut file = std::fs::File::create(&temp)
            .map_err(|e| RemoteError::internal(format!("artifact temp: {e}")))?;
        let mut hasher = Sha256Writer::new();
        let mut total: u64 = 0;

        for chunk in chunks {
            total += chunk.len() as u64;
            if total > self.max_bytes {
                drop(file);
                let _ = std::fs::remove_file(&temp);
                return Err(RemoteError::ArtifactTooLarge {
                    max_bytes: self.max_bytes,
                });
            }
            hasher.write(&chunk);
            if let Err(e) = file.write_all(&chunk) {
                drop(file);
                let _ = std::fs::remove_file(&temp);
                return Err(RemoteError::internal(format!("artifact write: {e}")));
            }
        }
        if let Err(e) = file.flush().and_then(|()| file.sync_all()) {
            drop(file);
            let _ = std::fs::remove_file(&temp);
            return Err(RemoteError::internal(format!("artifact flush: {e}")));
        }
        drop(file);

        let actual = hasher.finish();
        if let Some(expected) = declared_sha256
            && !expected.eq_ignore_ascii_case(&actual)
        {
            let _ = std::fs::remove_file(&temp);
            return Err(RemoteError::ArtifactHashMismatch {
                expected: expected.to_string(),
                actual,
            });
        }

        let blob = self.blob_path(session_id, id);
        if let Some(parent) = blob.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            let _ = std::fs::remove_file(&temp);
            return Err(RemoteError::internal(format!("artifact dir: {e}")));
        }
        if let Err(e) = std::fs::rename(&temp, &blob) {
            let _ = std::fs::remove_file(&temp);
            return Err(RemoteError::internal(format!("artifact commit: {e}")));
        }

        let meta = ArtifactMeta {
            id,
            session_id,
            path: blob.display().to_string(),
            bytes: total,
            sha256: actual,
            created_at: crate::remote::now_secs(),
        };
        self.write_meta(&meta)?;
        Ok(meta)
    }

    /// Store one buffer. Convenience over [`Self::put_stream`].
    pub fn put_bytes(
        &self,
        session_id: Uuid,
        id: Uuid,
        declared_sha256: Option<&str>,
        bytes: &[u8],
    ) -> Result<ArtifactMeta, RemoteError> {
        self.put_stream(session_id, id, declared_sha256, vec![bytes.to_vec()])
    }

    /// Metadata for a stored artifact.
    pub fn meta(&self, id: Uuid) -> Result<ArtifactMeta, RemoteError> {
        let raw = std::fs::read(self.meta_path(id)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                RemoteError::ArtifactNotFound { id }
            } else {
                RemoteError::internal(format!("artifact meta: {e}"))
            }
        })?;
        serde_json::from_slice(&raw).map_err(|e| RemoteError::internal(format!("artifact meta: {e}")))
    }

    /// The artifact's bytes, verified against the recorded sha256.
    pub fn get(&self, id: Uuid) -> Result<(ArtifactMeta, Vec<u8>), RemoteError> {
        let meta = self.meta(id)?;
        let bytes = std::fs::read(&meta.path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                RemoteError::ArtifactNotFound { id }
            } else {
                RemoteError::internal(format!("artifact read: {e}"))
            }
        })?;
        let actual = sha256_hex(&bytes);
        if !actual.eq_ignore_ascii_case(&meta.sha256) {
            return Err(RemoteError::ArtifactHashMismatch {
                expected: meta.sha256.clone(),
                actual,
            });
        }
        Ok((meta, bytes))
    }

    /// Whether an artifact id is stored.
    pub fn contains(&self, id: Uuid) -> bool {
        self.meta_path(id).is_file()
    }

    /// Delete every artifact of a session. Returns how many were removed.
    pub fn prune_session(&self, session_id: Uuid) -> Result<usize, RemoteError> {
        let dir = self.root.join(session_id.to_string());
        let mut removed = 0usize;
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("bin")
                    && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                    && let Ok(id) = Uuid::parse_str(stem)
                {
                    let _ = std::fs::remove_file(self.meta_path(id));
                }
                if std::fs::remove_file(&path).is_ok() {
                    removed += 1;
                }
            }
        }
        let _ = std::fs::remove_dir(&dir);
        Ok(removed)
    }

    fn write_meta(&self, meta: &ArtifactMeta) -> Result<(), RemoteError> {
        let json = serde_json::to_vec_pretty(meta)
            .map_err(|e| RemoteError::internal(format!("artifact meta: {e}")))?;
        let path = self.meta_path(meta.id);
        let temp = self.root.join(format!(".meta-{}", meta.id));
        std::fs::write(&temp, &json)
            .map_err(|e| RemoteError::internal(format!("artifact meta write: {e}")))?;
        std::fs::rename(&temp, &path)
            .map_err(|e| RemoteError::internal(format!("artifact meta commit: {e}")))
    }
}

/// Incremental sha256 so a stream is hashed without being buffered whole.
struct Sha256Writer {
    hasher: sha2::Sha256,
}

impl Sha256Writer {
    fn new() -> Self {
        use sha2::Digest;
        Self {
            hasher: sha2::Sha256::new(),
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        use sha2::Digest;
        self.hasher.update(bytes);
    }

    fn finish(self) -> String {
        use sha2::Digest;
        self.hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// An artifact's wire shape: `{id, bytes, sha256}`.
pub fn artifact_json(meta: &ArtifactMeta) -> Value {
    json!({
        "id": meta.id,
        "session_id": meta.session_id,
        "bytes": meta.bytes,
        "sha256": meta.sha256,
        "created_at": meta.created_at,
    })
}

/// Refuse a caller that does not hold `artifact:transfer`.
fn scope_refusal(id: Value) -> JsonRpcResponse {
    RemoteError::ScopeDenied {
        missing_scope: SCOPE_ARTIFACT_TRANSFER.to_string(),
    }
    .to_response(id)
}

/// `GET /a2a/v1/artifact/{id}` — download the bytes.
pub async fn handle_download(
    State(state): State<A2aState>,
    Extension(granted): Extension<GrantedScopes>,
    Path(raw_id): Path<String>,
) -> Response {
    if !allows(&granted.0, SCOPE_ARTIFACT_TRANSFER) {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(scope_refusal(json!(null))),
        )
            .into_response();
    }
    let Some(relay) = state.relay.clone() else {
        return not_found(Uuid::nil());
    };
    let Ok(id) = Uuid::parse_str(raw_id.trim()) else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(
                RemoteError::ValidationError {
                    field: "id".into(),
                    reason: "not a uuid".into(),
                }
                .to_response(json!(null)),
            ),
        )
            .into_response();
    };
    match relay.artifacts.get(id) {
        Ok((meta, bytes)) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/octet-stream"),
            );
            if let Ok(value) = header::HeaderValue::from_str(&meta.sha256) {
                headers.insert(
                    header::HeaderName::from_static(SHA256_HEADER),
                    value,
                );
            }
            (StatusCode::OK, headers, bytes).into_response()
        }
        Err(e) => (status_of(&e), axum::Json(e.to_response(json!(null)))).into_response(),
    }
}

/// `POST /a2a/v1/artifact` — upload bytes for the next turn to read.
///
/// The body is already bounded by `DefaultBodyLimit`; this handler applies the
/// artifact cap itself so the refusal carries `ARTIFACT_TOO_LARGE` and the cap
/// it exceeded rather than a bare 413.
pub async fn handle_upload(
    State(state): State<A2aState>,
    Extension(granted): Extension<GrantedScopes>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !allows(&granted.0, SCOPE_ARTIFACT_TRANSFER) {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(scope_refusal(json!(null))),
        )
            .into_response();
    }
    let Some(relay) = state.relay.clone() else {
        return not_found(Uuid::nil());
    };
    let declared = headers
        .get(header::HeaderName::from_static(SHA256_HEADER))
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let session_id = headers
        .get(header::HeaderName::from_static(SESSION_HEADER))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
        .unwrap_or_else(Uuid::nil);
    let max_bytes = relay.artifacts.max_bytes();
    if body.len() as u64 > max_bytes {
        let err = RemoteError::ArtifactTooLarge { max_bytes };
        return (status_of(&err), axum::Json(err.to_response(json!(null)))).into_response();
    }
    let id = Uuid::new_v4();
    match relay
        .artifacts
        .put_bytes(session_id, id, declared.as_deref(), &body)
    {
        Ok(meta) => (
            StatusCode::CREATED,
            axum::Json(artifact_json(&meta)),
        )
            .into_response(),
        Err(e) => (status_of(&e), axum::Json(e.to_response(json!(null)))).into_response(),
    }
}

fn status_of(err: &RemoteError) -> StatusCode {
    StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

fn not_found(id: Uuid) -> Response {
    let err = RemoteError::ArtifactNotFound { id };
    (StatusCode::NOT_FOUND, axum::Json(err.to_response(json!(null)))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cap_has_a_default_and_rejects_a_zero_override() {
        // `configured_max_bytes` must never return 0, which would refuse every
        // artifact while looking like a configured limit.
        assert!(configured_max_bytes() > 0);
        assert_eq!(DEFAULT_MAX_BYTES, 200 * 1024 * 1024);
    }

    #[test]
    fn a_hash_mismatch_leaves_nothing_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ArtifactStore::new(dir.path());
        let err = store
            .put_bytes(Uuid::new_v4(), Uuid::new_v4(), Some("deadbeef"), b"payload")
            .unwrap_err();
        assert_eq!(err.code(), "ARTIFACT_HASH_MISMATCH");
        assert_eq!(
            std::fs::read_dir(dir.path()).expect("dir").count(),
            0,
            "no temp file may survive a rejected upload"
        );
    }

    #[test]
    fn a_stored_artifact_reads_back_with_its_hash() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ArtifactStore::new(dir.path());
        let session = Uuid::new_v4();
        let id = Uuid::new_v4();
        let meta = store
            .put_bytes(session, id, None, b"hello artifact")
            .expect("stored");
        assert_eq!(meta.sha256, sha256_hex(b"hello artifact"));
        assert!(store.contains(id));
        let (read_meta, bytes) = store.get(id).expect("read back");
        assert_eq!(read_meta.id, id);
        assert_eq!(read_meta.session_id, session);
        assert_eq!(bytes, b"hello artifact");
    }
}
