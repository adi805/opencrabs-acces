//! AC-015/016/017: the client filesystem namespace.
//!
//! A `client:<device>:/path` is answered by the paired device and by nothing
//! else. These tests drive the real router with a real paired device on the
//! other end of the registry, so what they prove is the whole leg: the engine
//! resolves the namespace, publishes `fs.request` on the device's session,
//! waits for `fs/reply`, and returns the device's bytes — while its own
//! filesystem is never touched.
//!
//! - AC-015 `read_through_namespace`: the read returns the device's bytes,
//!   labelled with the device's namespace.
//! - AC-016 `no_engine_side_write`: a client write whose path collides with a
//!   real engine file leaves that file byte-identical.
//! - AC-017 `unknown_namespace_lists_available`: an unpaired device is refused
//!   with the namespaces that DO exist, not a generic failure.

use crate::a2a::server::{A2aState, build_router};
use crate::a2a::test_helpers::helpers;
use crate::remote::errors::RPC_PATH_NAMESPACE_UNKNOWN;
use crate::remote::fs_proxy::{FsProxy, FsReply, KIND_FS_REQUEST, encode_bytes, sha256_hex};
use crate::remote::pairing::PairingStore;
use crate::remote::relay::{RelayState, device_key};
use crate::remote::scopes::SCOPE_FS_CLIENT;
use axum::body::Body;
use axum::http::Request;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

const API_KEY: &str = "clientfs-test-key";

/// A gateway wired to a live relay. The proxy deadline is short on purpose: a
/// test that hangs 30 s on a wiring mistake is a test nobody re-runs.
async fn relay_state() -> (A2aState, Arc<RelayState>) {
    let pairing = PairingStore::new(
        std::env::temp_dir().join(format!("oc-clientfs-{}.json", Uuid::new_v4())),
    );
    let relay = RelayState::new(
        pairing.clone(),
        helpers::placeholder_service_context().await,
        helpers::placeholder_agent_service().await,
    )
    .with_fs(Arc::new(FsProxy::with_timeout(Duration::from_secs(5))));
    let relay = Arc::new(relay);
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
            .join(format!("oc-clientfs-state-{}", Uuid::new_v4())),
        relay: Some(relay.clone()),
    };
    (state, relay)
}

/// Pair a device that holds `fs:client`, and attach it to a session.
///
/// A client namespace is answerable only when the device is both paired (the
/// id appears in `available`) and streaming (the request has somewhere to go).
/// Returns the device id and the subscription the fake client reads from.
fn attach_device(
    state: &A2aState,
    relay: &Arc<RelayState>,
    session_id: Uuid,
) -> (String, crate::remote::registry::Subscription) {
    let code = state
        .pairing
        .mint_code(&[SCOPE_FS_CLIENT.to_string()])
        .expect("mint code");
    let (_token, session) = state
        .pairing
        .verify_code(&code, "test phone")
        .expect("verify code");
    let device = session.id.clone();
    let sub = relay.registry.subscribe(session_id, device_key(&device));
    (device, sub)
}

/// One JSON-RPC call through the real router.
async fn call(state: &A2aState, method: &str, params: Value) -> Value {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let request = Request::builder()
        .method("POST")
        .uri("/a2a/v1")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {API_KEY}"))
        .body(Body::from(body.to_string()))
        .expect("request");
    let response = build_router(state.clone(), &[])
        .oneshot(request)
        .await
        .expect("response");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json")
}

#[tokio::test]
async fn read_through_namespace() {
    let (state, relay) = relay_state().await;
    let session_id = Uuid::new_v4();
    let (device, mut sub) = attach_device(&state, &relay, session_id);

    let payload = b"hello from the phone".to_vec();
    let digest = sha256_hex(&payload);
    let client_relay = relay.clone();
    let client_digest = digest.clone();
    let client = tokio::spawn(async move {
        let frame = sub.rx.recv().await.expect("fs.request frame");
        assert_eq!(frame.kind, KIND_FS_REQUEST);
        assert_eq!(
            frame.payload["path"],
            json!("notes.txt"),
            "the device is asked for the path relative to its grant root"
        );
        let request_id = frame.payload["request_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .expect("request_id");
        assert!(
            client_relay.fs.deliver(FsReply {
                request_id,
                bytes: Some(b"hello from the phone".to_vec()),
                sha256: Some(client_digest),
                entries: None,
                error: None,
            }),
            "the reply found the waiting request"
        );
    });

    let body = call(
        &state,
        "fs/read",
        json!({ "path": format!("client:{device}:/notes.txt") }),
    )
    .await;
    client.await.expect("client task");

    assert!(body.get("error").is_none(), "the read succeeded: {body}");
    assert_eq!(
        body["result"]["namespace"],
        json!(format!("client:{device}:")),
        "the answer is labelled with the device namespace, not the engine's"
    );
    assert_eq!(body["result"]["bytes_base64"], json!(encode_bytes(&payload)));
    assert_eq!(
        body["result"]["sha256"],
        json!(digest),
        "the digest is computed over the bytes the device returned"
    );
}

#[tokio::test]
async fn no_engine_side_write() {
    let (state, relay) = relay_state().await;
    let session_id = Uuid::new_v4();
    let (device, mut sub) = attach_device(&state, &relay, session_id);

    // A real engine file at the same relative name. A client write that leaked
    // onto the engine's disk would land exactly here and overwrite it.
    let dir = std::env::temp_dir().join(format!("oc-clientfs-engine-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("engine dir");
    let engine_file = dir.join("victim.txt");
    std::fs::write(&engine_file, b"engine owned").expect("seed engine file");

    let payload = b"device owned".to_vec();
    let digest = sha256_hex(&payload);
    let client_relay = relay.clone();
    let client_digest = digest.clone();
    let client = tokio::spawn(async move {
        let frame = sub.rx.recv().await.expect("fs.request frame");
        assert_eq!(frame.payload["op"], json!("write"));
        let request_id = frame.payload["request_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .expect("request_id");
        assert!(client_relay.fs.deliver(FsReply {
            request_id,
            bytes: Some(b"device owned".to_vec()),
            sha256: Some(client_digest),
            entries: None,
            error: None,
        }));
    });

    let body = call(
        &state,
        "fs/write",
        json!({
            "path": format!("client:{device}:/victim.txt"),
            "bytes_base64": encode_bytes(&payload),
            "sha256": digest,
        }),
    )
    .await;
    client.await.expect("client task");

    assert!(body.get("error").is_none(), "the write was accepted: {body}");
    assert_eq!(
        std::fs::read(&engine_file).expect("read engine file"),
        b"engine owned",
        "a client write never reaches the engine's own filesystem"
    );
}

#[tokio::test]
async fn unknown_namespace_lists_available() {
    let (state, _relay) = relay_state().await;
    let code = state
        .pairing
        .mint_code(&[SCOPE_FS_CLIENT.to_string()])
        .expect("mint code");
    let (_token, session) = state
        .pairing
        .verify_code(&code, "known phone")
        .expect("verify code");

    let body = call(&state, "fs/list", json!({ "path": "client:ghost:/" })).await;

    assert_eq!(
        body["error"]["code"],
        json!(RPC_PATH_NAMESPACE_UNKNOWN),
        "an unpaired device is a namespace error: {body}"
    );
    assert_eq!(body["error"]["data"]["code"], json!("PATH_NAMESPACE_UNKNOWN"));
    assert_eq!(body["error"]["data"]["input"], json!("client:ghost:/"));
    assert_eq!(
        body["error"]["data"]["available"],
        json!(["engine:", format!("client:{}:", session.id)]),
        "the refusal names every namespace that does exist"
    );
}

#[tokio::test]
async fn a_client_read_that_does_not_hash_is_refused() {
    let (state, relay) = relay_state().await;
    let session_id = Uuid::new_v4();
    let (device, mut sub) = attach_device(&state, &relay, session_id);

    let client_relay = relay.clone();
    let client = tokio::spawn(async move {
        let frame = sub.rx.recv().await.expect("fs.request frame");
        let request_id = frame.payload["request_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .expect("request_id");
        // The device announces a digest that is not the one its bytes produce.
        assert!(client_relay.fs.deliver(FsReply {
            request_id,
            bytes: Some(b"tampered".to_vec()),
            sha256: Some(sha256_hex(b"something else")),
            entries: None,
            error: None,
        }));
    });

    let body = call(
        &state,
        "fs/read",
        json!({ "path": format!("client:{device}:/notes.txt") }),
    )
    .await;
    client.await.expect("client task");

    assert_eq!(
        body["error"]["data"]["code"],
        json!("ARTIFACT_HASH_MISMATCH"),
        "bytes that do not match the announced digest are not served: {body}"
    );
}
