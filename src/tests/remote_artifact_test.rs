//! AC-018/019/020: artifact transfer over plain HTTP.
//!
//! An artifact is bytes, so it rides beside the JSON-RPC surface rather than
//! inside it. Three properties, each one a test:
//!
//! - AC-018 `download_hash_matches`: a downloaded artifact hashes to the
//!   digest the upload recorded, and that digest is handed to the client in
//!   `X-Content-SHA256` so it can verify without a second round trip.
//! - AC-019 `upload_roundtrip`: bytes in, `{id, bytes, sha256}` out, and the
//!   same bytes come back out of the download route.
//! - AC-020 `oversized_rejected_clean`: an upload past the cap is refused with
//!   `ARTIFACT_TOO_LARGE` and leaves nothing on disk — no partial file that a
//!   later reader could mistake for a short artifact.

use crate::a2a::server::{A2aState, build_router};
use crate::a2a::test_helpers::helpers;
use crate::remote::artifact::{ArtifactStore, SHA256_HEADER};
use crate::remote::errors::RPC_ARTIFACT_TOO_LARGE;
use crate::remote::fs_proxy::sha256_hex;
use crate::remote::pairing::PairingStore;
use crate::remote::relay::RelayState;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const API_KEY: &str = "artifact-test-key";

/// A gateway whose artifact store is a temp directory, so a test never touches
/// the profile's real `state/remote/artifacts`.
async fn state_with_store(max_bytes: Option<u64>) -> (A2aState, Arc<ArtifactStore>, PathBuf) {
    let root = std::env::temp_dir().join(format!("oc-artifacts-{}", Uuid::new_v4()));
    let store = match max_bytes {
        Some(max) => ArtifactStore::with_max_bytes(root.clone(), max),
        None => ArtifactStore::new(root.clone()),
    };
    let store = Arc::new(store);
    let pairing = PairingStore::new(
        std::env::temp_dir().join(format!("oc-artifacts-pairing-{}.json", Uuid::new_v4())),
    );
    let relay = RelayState::new(
        pairing.clone(),
        helpers::placeholder_service_context().await,
        helpers::placeholder_agent_service().await,
    )
    .with_artifacts(store.clone());
    let state = A2aState {
        task_store: crate::a2a::handler::new_task_store(),
        cancel_store: crate::a2a::handler::new_cancel_store(),
        host: "127.0.0.1".to_string(),
        port: 18790,
        agent_service: helpers::placeholder_agent_service().await,
        service_context: helpers::placeholder_service_context().await,
        api_key: Some(API_KEY.to_string()),
        pairing,
        pair_hits: crate::a2a::pairing_http::new_pair_hits(),
        remote_state_dir: std::env::temp_dir()
            .join(format!("oc-artifacts-state-{}", Uuid::new_v4())),
        relay: Some(Arc::new(relay)),
    };
    (state, store, root)
}

/// `POST /a2a/v1/artifact`.
async fn upload(
    state: &A2aState,
    bytes: Vec<u8>,
    declared_sha256: Option<&str>,
    session_id: Option<Uuid>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/a2a/v1/artifact")
        .header("content-type", "application/octet-stream")
        .header("authorization", format!("Bearer {API_KEY}"));
    if let Some(digest) = declared_sha256 {
        builder = builder.header(SHA256_HEADER, digest);
    }
    if let Some(id) = session_id {
        builder = builder.header("x-session-id", id.to_string());
    }
    let request = builder.body(Body::from(bytes)).expect("request");
    let response = build_router(state.clone(), &[])
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json = if body.is_empty() {
        json!(null)
    } else {
        serde_json::from_slice(&body).unwrap_or(json!(null))
    };
    (status, json)
}

/// `GET /a2a/v1/artifact/{id}` — status, announced digest, bytes.
async fn download(state: &A2aState, id: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    let request = Request::builder()
        .method("GET")
        .uri(format!("/a2a/v1/artifact/{id}"))
        .header("authorization", format!("Bearer {API_KEY}"))
        .body(Body::empty())
        .expect("request");
    let response = build_router(state.clone(), &[])
        .oneshot(request)
        .await
        .expect("response");
    let status = response.status();
    let digest = response
        .headers()
        .get(SHA256_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec();
    (status, digest, bytes)
}

#[tokio::test]
async fn download_hash_matches() {
    let (state, _store, _root) = state_with_store(None).await;
    let payload = b"a report the engine produced".to_vec();
    let digest = sha256_hex(&payload);

    let (status, meta) = upload(&state, payload.clone(), Some(&digest), None).await;
    assert_eq!(status, StatusCode::CREATED, "upload accepted: {meta}");
    let id = meta["id"].as_str().expect("id").to_string();

    let (status, announced, bytes) = download(&state, &id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, payload, "the bytes come back unchanged");
    assert_eq!(
        announced.as_deref(),
        Some(digest.as_str()),
        "the download announces the digest so the client can verify locally"
    );
    assert_eq!(
        sha256_hex(&bytes),
        digest,
        "AC-018: the downloaded bytes hash to the recorded digest"
    );
}

#[tokio::test]
async fn upload_roundtrip() {
    let (state, _store, _root) = state_with_store(None).await;
    let session = Uuid::new_v4();
    let payload = b"client uploads this for the next turn to read".to_vec();
    let digest = sha256_hex(&payload);

    let (status, meta) = upload(&state, payload.clone(), Some(&digest), Some(session)).await;
    assert_eq!(status, StatusCode::CREATED, "upload accepted: {meta}");
    assert_eq!(meta["bytes"], json!(payload.len()));
    assert_eq!(meta["sha256"], json!(digest));
    let id = meta["id"].as_str().expect("id").to_string();

    let (status, announced, bytes) = download(&state, &id).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, payload, "AC-019: the roundtrip is byte-identical");
    assert_eq!(announced.as_deref(), Some(digest.as_str()));
}

#[tokio::test]
async fn oversized_rejected_clean() {
    // A 1 KiB cap and a 2 KiB body: the refusal is the store's, not axum's,
    // so it carries the cap that was exceeded.
    let cap = 1024u64;
    let (state, _store, root) = state_with_store(Some(cap)).await;
    let payload = vec![7u8; 2048];

    let (status, body) = upload(&state, payload, None, None).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "413 on oversize: {body}");
    assert_eq!(
        body["error"]["code"],
        json!(RPC_ARTIFACT_TOO_LARGE),
        "the refusal is ARTIFACT_TOO_LARGE, not a bare 413: {body}"
    );
    assert_eq!(body["error"]["data"]["code"], json!("ARTIFACT_TOO_LARGE"));
    assert_eq!(body["error"]["data"]["max_bytes"], json!(cap));

    // AC-020: nothing landed. Either the store never created its root, or it
    // is empty — a partial file would show up as a directory entry.
    if root.exists() {
        let entries: Vec<_> = std::fs::read_dir(&root)
            .expect("read artifact root")
            .collect();
        assert!(
            entries.is_empty(),
            "a rejected upload leaves no partial file behind: {entries:?}"
        );
    }
}

#[tokio::test]
async fn an_unknown_artifact_is_not_found() {
    let (state, _store, _root) = state_with_store(None).await;
    let (status, announced, _bytes) = download(&state, &Uuid::new_v4().to_string()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(announced.is_none(), "no digest is announced for a miss");
}

#[tokio::test]
async fn a_body_that_does_not_match_its_digest_is_refused() {
    let (state, store, _root) = state_with_store(None).await;
    let payload = b"bytes".to_vec();
    let wrong = sha256_hex(b"different bytes");

    let (status, body) = upload(&state, payload, Some(&wrong), None).await;
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a hash mismatch is 422: {body}"
    );
    assert_eq!(
        body["error"]["data"]["code"],
        json!("ARTIFACT_HASH_MISMATCH"),
        "{body}"
    );
    assert_eq!(
        store.max_bytes(),
        crate::remote::artifact::DEFAULT_MAX_BYTES,
        "the store was untouched by the refusal"
    );
}
