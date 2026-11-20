//! AC-003: a token without `session:send` cannot send, and the refusal mutates
//! nothing.
//!
//! The gate is tested through the real router with a real `ocpair_` token, not
//! by calling the scope helper: the ordering (authorize before dispatch) is the
//! property, and only an end-to-end call proves it.

use crate::a2a::server::{A2aState, build_router};
use crate::a2a::test_helpers::helpers;
use crate::a2a::types::error_codes;
use crate::db::repository::SessionRepository;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use uuid::Uuid;

async fn state() -> A2aState {
    A2aState {
        task_store: crate::a2a::handler::new_task_store(),
        cancel_store: crate::a2a::handler::new_cancel_store(),
        host: "127.0.0.1".to_string(),
        port: 18790,
        agent_service: helpers::placeholder_agent_service().await,
        service_context: helpers::placeholder_service_context().await,
        api_key: None,
        pairing: crate::remote::pairing::PairingStore::new(std::env::temp_dir().join(format!(
            "oc-scope-denied-{}-{}.json",
            std::process::id(),
            Uuid::new_v4()
        ))),
        pair_hits: crate::a2a::pairing_http::new_pair_hits(),
        remote_state_dir: std::env::temp_dir()
            .join(format!("oc-scope-denied-state-{}", Uuid::new_v4())),
        relay: None,
    }
}

fn send_request(token: &str, session_id: Uuid) -> Request<Body> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "session/send",
        "params": { "session_id": session_id.to_string(), "text": "hello" },
    });
    Request::builder()
        .method("POST")
        .uri("/a2a/v1")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .expect("request")
}

#[tokio::test]
async fn denied_scope_writes_nothing() {
    let state = state().await;
    let session = crate::db::models::Session::new(Some("scope".to_string()), None, None);
    SessionRepository::new(state.service_context.pool())
        .create(&session)
        .await
        .expect("create session");

    // A read-only token: exactly the scopes a phone that may only watch holds.
    let code = state
        .pairing
        .mint_code(&[crate::remote::scopes::SCOPE_READ.to_string()])
        .expect("mint");
    let (token, _) = state.pairing.verify_code(&code, "read only").expect("verify");

    let app = build_router(state.clone(), &[]);
    let resp = app
        .oneshot(send_request(&token, session.id))
        .await
        .expect("response");

    assert_eq!(resp.status(), StatusCode::OK, "JSON-RPC errors ride HTTP 200");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(
        body["error"]["code"],
        serde_json::json!(error_codes::INSUFFICIENT_SCOPE),
        "the call is refused for want of a scope: {body}"
    );

    // Nothing was admitted: the gate runs before dispatch, so no turn, no
    // message and no sequence entry can exist.
    assert!(
        state.relay.is_none(),
        "no relay was wired, so any dispatch would have failed differently"
    );
}

#[tokio::test]
async fn a_token_with_the_scope_clears_the_gate() {
    let state = state().await;
    let code = state
        .pairing
        .mint_code(&[crate::remote::scopes::SCOPE_SESSION_SEND.to_string()])
        .expect("mint");
    let (token, _) = state.pairing.verify_code(&code, "sender").expect("verify");

    let app = build_router(state.clone(), &[]);
    let resp = app
        .oneshot(send_request(&token, Uuid::new_v4()))
        .await
        .expect("response");
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");

    assert_ne!(
        body["error"]["code"],
        serde_json::json!(error_codes::INSUFFICIENT_SCOPE),
        "the scope check passed, so the refusal is a missing relay: {body}"
    );
    assert_eq!(
        body["error"]["code"],
        serde_json::json!(error_codes::METHOD_NOT_FOUND)
    );
}
