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
//!   labelled with the device's namespace, and a device that never answers
//!   surfaces `CLIENT_OFFLINE` at the deadline instead of hanging.
//! - AC-016 `no_engine_side_write`: a client write whose path collides with a
//!   real engine file leaves that file byte-identical.
//! - AC-017 `unknown_namespace_lists_available`: a path with no namespace is
//!   refused with every namespace that DOES exist, not a generic failure.

use crate::a2a::server::{A2aState, build_router};
use crate::a2a::test_helpers::helpers;
use crate::remote::errors::{RPC_CLIENT_OFFLINE, RPC_PATH_NAMESPACE_UNKNOWN};
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
    relay_state_with_timeout(Duration::from_secs(5)).await
}

/// Same wiring, with an explicit reply deadline so the silence test can prove
/// a timeout in milliseconds instead of the shipped `FS_REPLY_TIMEOUT`.
async fn relay_state_with_timeout(timeout: Duration) -> (A2aState, Arc<RelayState>) {
    let pairing = PairingStore::new(
        std::env::temp_dir().join(format!("oc-clientfs-{}.json", Uuid::new_v4())),
    );
    let relay = RelayState::new(
        pairing.clone(),
        helpers::placeholder_service_context().await,
        helpers::placeholder_agent_service().await,
    )
    .with_fs(Arc::new(FsProxy::with_timeout(timeout)));
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

/// Read the next `fs.request` off a device's stream.
///
/// Taking the subscription by value is what makes the fake client read as the
/// device would: the engine publishes, the device's stream yields, and the
/// request is answered on the same leg.
async fn next_request(mut sub: crate::remote::registry::Subscription) -> Arc<crate::remote::seq::Frame> {
    sub.rx.recv().await.expect("fs.request frame")
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
    let (device, sub) = attach_device(&state, &relay, session_id);

    let payload = b"hello from the phone".to_vec();
    let digest = sha256_hex(&payload);
    let client_relay = relay.clone();
    let client_digest = digest.clone();
    let client = tokio::spawn(async move {
        let frame = next_request(sub).await;
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

    // AC-015, second half: a device that never answers must surface
    // CLIENT_OFFLINE at the deadline instead of hanging the request. The
    // deadline is shortened to 300 ms here so the suite stays fast; the
    // shipped default is FS_REPLY_TIMEOUT (30 s).
    let (silent_state, silent_relay) =
        relay_state_with_timeout(Duration::from_millis(300)).await;
    let (silent_device, _silent_sub) =
        attach_device(&silent_state, &silent_relay, Uuid::new_v4());
    let body = call(
        &silent_state,
        "fs/read",
        json!({ "path": format!("client:{silent_device}:/notes.txt") }),
    )
    .await;
    assert_eq!(
        body["error"]["code"],
        json!(RPC_CLIENT_OFFLINE),
        "a silent device times out instead of hanging: {body}"
    );
    assert_eq!(body["error"]["data"]["code"], json!("CLIENT_OFFLINE"));
}

#[tokio::test]
async fn no_engine_side_write() {
    let (state, relay) = relay_state().await;
    let session_id = Uuid::new_v4();
    let (device, sub) = attach_device(&state, &relay, session_id);

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
        let frame = next_request(sub).await;
        assert_eq!(frame.payload["op"], json!("write"));
        assert_eq!(
            frame.payload["path"],
            json!("victim.txt"),
            "the device is handed a path relative to its grant root, so the write \
             can only land inside the folder it granted"
        );
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
        body["result"]["namespace"],
        json!(format!("client:{device}:")),
        "the write is acknowledged under the client namespace, not the engine's"
    );
    assert_eq!(
        std::fs::read(&engine_file).expect("read engine file"),
        b"engine owned",
        "a client write never reaches the engine's own filesystem"
    );
}

#[tokio::test]
async fn unknown_namespace_lists_available() {
    // AC-017: a bare Windows path carries no namespace, so the engine cannot
    // know which filesystem it names. The refusal has to enumerate every
    // namespace that does exist (the engine plus each paired device) so the
    // caller can retry without guessing.
    let (state, relay) = relay_state().await;
    let (device_b, _sub_b) = attach_device(&state, &relay, Uuid::new_v4());
    let (device_c, _sub_c) = attach_device(&state, &relay, Uuid::new_v4());

    let body = call(
        &state,
        "fs/list",
        json!({ "path": r"C:\Users\alice\notes.txt" }),
    )
    .await;

    assert_eq!(
        body["error"]["code"],
        json!(RPC_PATH_NAMESPACE_UNKNOWN),
        "a path with no namespace is a namespace error: {body}"
    );
    assert_eq!(body["error"]["data"]["code"], json!("PATH_NAMESPACE_UNKNOWN"));
    assert_eq!(
        body["error"]["data"]["input"],
        json!(r"C:\Users\alice\notes.txt")
    );

    // Order is not part of the contract (the pairing store does not promise
    // one), so compare as a set: engine plus both attached devices.
    let mut got: Vec<String> = body["error"]["data"]["available"]
        .as_array()
        .expect("available list")
        .iter()
        .map(|v| v.as_str().expect("namespace string").to_string())
        .collect();
    got.sort();
    let mut want = vec![
        "engine:".to_string(),
        format!("client:{device_b}:"),
        format!("client:{device_c}:"),
    ];
    want.sort();
    assert_eq!(got, want, "the refusal names every namespace that does exist");
}

#[tokio::test]
async fn an_unpaired_device_is_a_namespace_error() {
    // A device id that is not paired is a namespace error too, and the same
    // list comes back — a mistyped id needs the ids that are actually valid.
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
    let (device, sub) = attach_device(&state, &relay, session_id);

    let client_relay = relay.clone();
    let client = tokio::spawn(async move {
        let frame = next_request(sub).await;
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
