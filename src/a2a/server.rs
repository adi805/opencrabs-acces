//! A2A Gateway HTTP server powered by axum.
//!
//! Serves:
//! - `GET  /.well-known/agent.json` — Agent Card discovery
//! - `POST /a2a/v1`                 — JSON-RPC 2.0 endpoint (scoped)
//! - `POST /a2a/pair`               — One-time code → scoped session token
//! - `GET  /a2a/health`             — Health check

use crate::a2a::{agent_card, handler, pairing_http, routes_http, types::*};
use crate::brain::agent::service::AgentService;
use crate::config::A2aConfig;
use crate::remote::pairing::PairingStore;
use crate::remote::relay::RelayState;
use crate::remote::scopes::{ALL_SCOPES, allows, scope_for_method};
use crate::services::ServiceContext;
use axum::{
    Extension, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Json, Sse, sse},
    routing::{get, post},
};
use futures::stream;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Shared state for the A2A gateway.
#[derive(Clone)]
pub struct A2aState {
    pub task_store: handler::TaskStore,
    pub cancel_store: handler::CancelStore,
    pub host: String,
    pub port: u16,
    pub agent_service: Arc<AgentService>,
    pub service_context: ServiceContext,
    pub api_key: Option<String>,
    /// Paired-session store (codes + tokens). Path-injected for tests.
    pub pairing: PairingStore,
    /// Per-client rate-limit buckets for POST /a2a/pair.
    pub pair_hits: pairing_http::PairHits,
    /// Where remote state lives (host_id, tunnel.json, routes.json).
    /// Production: `<opencrabs_home>/state/remote`. Injected for tests.
    pub remote_state_dir: std::path::PathBuf,
    /// The remote shared-session relay. `None` keeps the gateway exactly as
    /// it was before the remote surface existed: every remote method answers
    /// `METHOD_NOT_FOUND`, so turning the surface off is a construction
    /// change rather than a code revert.
    pub relay: Option<Arc<RelayState>>,
}

/// The scopes a request's credential carries, attached by `require_bearer`
/// and enforced per method in `handle_jsonrpc`.
#[derive(Clone, Debug)]
pub struct GrantedScopes(pub Vec<String>);

/// The pairing identity a request authenticated as, when it used a device
/// token rather than the config api_key. `None` for the api_key and for the
/// legacy loopback-open posture.
#[derive(Clone, Debug)]
pub struct GrantedDevice(pub Option<String>);

fn all_scopes() -> Vec<String> {
    ALL_SCOPES.iter().map(|s| s.to_string()).collect()
}

/// Compare a presented bearer token against the configured one without a
/// timing side-channel on the secret.
///
/// A plain `token == expected` short-circuits at the first differing byte, so
/// the response time leaks how many leading bytes a guess got right and the
/// token can be recovered one byte at a time over the network. Hashing both
/// sides to a fixed-length SHA-256 digest first removes that: the digests are
/// always 32 bytes (no length leak), and an attacker cannot steer the digest
/// of a guess to walk the comparison, because that would require a SHA-256
/// preimage. This is the standard hash-then-compare mitigation and needs no
/// new dependency.
pub(crate) fn tokens_match(presented: &str, expected: &str) -> bool {
    use sha2::{Digest, Sha256};
    let a = Sha256::digest(presented.as_bytes());
    let b = Sha256::digest(expected.as_bytes());
    a == b
}

/// Bearer auth middleware. Two credential kinds:
///
/// - The config `[a2a].api_key` → all scopes (backward compatible).
/// - A paired `ocpair_` session token → the scopes its code carried.
///
/// When no api_key is configured the legacy loopback-open posture stands:
/// everything through (`check_gate_authenticated` guarantees that posture
/// can only bind loopback). Successful auth attaches [`GrantedScopes`] for
/// the per-method check in `handle_jsonrpc`.
async fn require_bearer(
    State(state): State<A2aState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> axum::response::Response {
    // Owned, not borrowed: `req.extensions_mut()` below needs the request
    // mutably while the token is still read afterwards.
    let presented = bearer_from_headers(req.headers()).map(str::to_string);
    let Some(scopes) = credential_scopes(&state, presented.as_deref()) else {
        return unauthorized_response();
    };
    req.extensions_mut().insert(GrantedScopes(scopes));
    // The device identity is only needed when the relay is on, and only a
    // device token carries one, so this costs nothing on the legacy path.
    let device = if state.relay.is_some() {
        presented
            .as_deref()
            .filter(|t| t.starts_with(crate::remote::pairing::TOKEN_PREFIX))
            .and_then(|t| state.pairing.verify_token(t).map(|s| s.id))
    } else {
        None
    };
    req.extensions_mut().insert(GrantedDevice(device));
    next.run(req).await
}

/// Extract the token from an `Authorization: Bearer <token>` header.
fn bearer_from_headers(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Resolve a presented credential to the scopes it grants, or `None` when
/// it authenticates nothing. Shared by `require_bearer` (the gate) and
/// `health_check` (the auth-gated routes block).
///
/// - No api_key configured → legacy loopback-open posture: everyone gets
///   all scopes (`check_gate_authenticated` keeps that posture loopback-only).
/// - The api_key itself → all scopes (backward compatible).
/// - An `ocpair_` session token → the scopes its pairing code carried.
pub(crate) fn credential_scopes(state: &A2aState, presented: Option<&str>) -> Option<Vec<String>> {
    match (&state.api_key, presented) {
        (None, _) => Some(all_scopes()),
        (Some(expected), Some(token)) if tokens_match(token, expected) => Some(all_scopes()),
        (Some(_), Some(token)) if token.starts_with(crate::remote::pairing::TOKEN_PREFIX) => {
            // Paired session. Small blocking JSON read per request: fine at
            // A2A rates, and the writer's atomic rename means never partial.
            state.pairing.verify_token(token).map(|s| s.scopes)
        }
        _ => None,
    }
}

fn unauthorized_response() -> axum::response::Response {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "error": { "code": -32001, "message": "Unauthorized: invalid or missing Bearer token" },
        "id": null
    });
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

/// Build the axum router for the A2A gateway.
pub fn build_router(state: A2aState, allowed_origins: &[String]) -> Router {
    let cors = if allowed_origins.is_empty() {
        CorsLayer::new()
    } else {
        let origins: Vec<_> = allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new().allow_origin(AllowOrigin::list(origins))
    };

    // Auth-protected JSON-RPC endpoint
    let protected = Router::new()
        .route("/a2a/v1", post(handle_jsonrpc))
        .route("/a2a/routes", get(routes_http::handle_routes))
        .merge(artifact_routes())
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ));

    // Public endpoints (discovery + health + pairing). Pairing is
    // unauthenticated by design — the one-time code IS the credential —
    // and rate-limited by a from_fn layer ahead of body extraction (so
    // malformed-JSON 400s still pay the toll; see pairing_http).
    Router::new()
        .route("/.well-known/agent.json", get(get_agent_card))
        .route("/a2a/health", get(health_check))
        .route("/a2a/pair", post(pairing_http::handle_pair))
        .route_layer(middleware::from_fn_with_state(
            state.pair_hits.clone(),
            pairing_http::pair_rate_limit,
        ))
        .merge(protected)
        .layer(cors)
        .with_state(state)
}

/// Artifact transfer routes: the only place in the gateway that moves raw
/// bytes instead of JSON.
///
/// Both routes sit behind `require_bearer`, so `GrantedScopes` is always
/// present and the handler can gate on `artifact:transfer`. The body limit is
/// the artifact cap plus one chunk of slack, on purpose: axum answers a limit
/// breach with a bare `413` and no body, which the client cannot tell apart
/// from a proxy error. Letting the request through to the handler means an
/// oversized upload comes back as a `RemoteError` carrying the cap it exceeded
/// (`ARTIFACT_TOO_LARGE`), which is what AC-020 asserts.
fn artifact_routes() -> Router<A2aState> {
    let slack = 1024 * 1024;
    let limit = crate::remote::artifact::configured_max_bytes().saturating_add(slack);
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    Router::new()
        .route(
            "/a2a/v1/artifact",
            post(crate::remote::artifact::handle_upload),
        )
        .route(
            "/a2a/v1/artifact/{id}",
            get(crate::remote::artifact::handle_download),
        )
        .layer(DefaultBodyLimit::max(limit))
}

/// Refuse an a2a bind that would be an open, unauthenticated gate.
///
/// The bearer token is the ONLY authorization boundary in front of the agent's
/// full tool surface: `send`/`stream` run the agent with tools for any caller
/// that clears `require_bearer`, and that middleware lets everyone through when
/// no key is set. Loopback is safe (only same-box callers reach the port); any
/// other bind with no key is an open tool-capable gate (#1473).
///
/// `Ok(())` means safe to start. A bind string that is not a bare IP never
/// parses into the `SocketAddr` the server needs either, so treating a parse
/// miss as "not loopback" only ever fails safe.
pub(crate) fn check_gate_authenticated(bind: &str, api_key: Option<&str>) -> Result<(), String> {
    if api_key.is_some() {
        return Ok(());
    }
    let loopback = bind
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false);
    if loopback {
        return Ok(());
    }
    Err(format!(
        "bind is '{bind}' (not loopback) with no api_key set, which would expose the agent's \
         full tool surface unauthenticated. Set [a2a].api_key, or bind to 127.0.0.1 (#1473)."
    ))
}

/// Start the A2A gateway server.
///
/// Runs as a background task — call from `tokio::spawn`.
///
/// If `ready` is provided, signals `Ok(())` once the socket is bound and
/// listening (or immediately if A2A is disabled), or signals `Err` if gate
/// validation, address parsing, or socket binding fails.
/// The socket is bound and listening when `ready` resolves `Ok(())`, so any
/// incoming connection is queued by the kernel accept queue and reaches the gateway.
pub async fn start_server(
    config: &A2aConfig,
    agent_service: Arc<AgentService>,
    service_context: ServiceContext,
    ready: Option<tokio::sync::oneshot::Sender<anyhow::Result<()>>>,
) -> anyhow::Result<()> {
    if !config.enabled {
        tracing::info!("A2A gateway disabled in config");
        if let Some(tx) = ready {
            let _ = tx.send(Ok(()));
        }
        return Ok(());
    }

    // The bearer token is the ONLY authorization boundary in front of the
    // agent's full tool surface here: `send`/`stream` run the agent with tools
    // for any caller that gets past this middleware, and `require_bearer` lets
    // everyone through when no key is set. That is fine on loopback, where only
    // same-box callers can reach the port. It is an open, unauthenticated,
    // tool-capable gate the moment the bind leaves loopback. Refuse rather than
    // start silently open (#1473). A hostname bind that is not a bare IP never
    // parsed into the SocketAddr below either, so treating a parse miss as
    // "not loopback" only ever fails safe.
    if let Err(reason) = check_gate_authenticated(&config.bind, config.api_key.as_deref()) {
        let msg = anyhow::anyhow!("A2A gateway refuses to start: {reason}");
        if let Some(tx) = ready {
            let _ = tx.send(Err(anyhow::anyhow!("{msg}")));
        }
        anyhow::bail!(msg);
    }

    // Restore any in-flight tasks from the database
    let task_store = handler::new_task_store();
    let persisted = super::persistence::load_active_tasks(&service_context.pool()).await;
    if !persisted.is_empty() {
        let mut store = task_store.write().await;
        for task in persisted {
            tracing::info!(
                "A2A: Restored task {} (state: {:?})",
                task.id,
                task.status.state
            );
            store.insert(task.id.clone(), task);
        }
    }

    let pairing_store = PairingStore::new(PairingStore::default_path());
    // The remote shared-session relay. Constructed here so the pairing store,
    // agent service and DB pool the gateway already owns are the same ones the
    // relay works through, never a second copy.
    let relay = Some(Arc::new(crate::remote::relay::RelayState::new(
        pairing_store.clone(),
        service_context.clone(),
        Arc::clone(&agent_service),
    )));

    let state = A2aState {
        task_store,
        cancel_store: handler::new_cancel_store(),
        host: config.bind.clone(),
        port: config.port,
        agent_service,
        service_context,
        api_key: config.api_key.clone(),
        pairing: pairing_store,
        pair_hits: pairing_http::new_pair_hits(),
        remote_state_dir: crate::remote::tunnel::default_state_dir(),
        relay,
    };

    // The reaper owns the same state dir the tunnel records into; capture it
    // before the router takes ownership of `state` (#2537).
    let reaper_dir = state.remote_state_dir.clone();
    let app = build_router(state, &config.allowed_origins);
    let addr: SocketAddr = match format!("{}:{}", config.bind, config.port).parse() {
        Ok(addr) => addr,
        Err(e) => {
            let err = anyhow::anyhow!("Invalid A2A gateway address: {}", e);
            if let Some(tx) = ready {
                let _ = tx.send(Err(anyhow::anyhow!("{err}")));
            }
            return Err(err);
        }
    };

    tracing::info!("A2A Gateway starting on http://{}", addr);
    tracing::info!("   Agent Card: http://{}/.well-known/agent.json", addr);
    tracing::info!("   JSON-RPC:   http://{}/a2a/v1", addr);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            let err = anyhow::anyhow!("A2A bind failed: {e}");
            if let Some(tx) = ready {
                let _ = tx.send(Err(anyhow::anyhow!("{err}")));
            }
            return Err(err);
        }
    };

    if let Some(tx) = ready {
        let _ = tx.send(Ok(()));
    }

    // A forgotten `connect` holds a public hostname until something stops it.
    // Nothing else in the daemon has a reason to look at the tunnel again, so
    // the stop condition is this timer (#2537).
    crate::remote::tunnel::spawn_idle_reaper(reaper_dir);

    // ConnectInfo makes the socket peer available to the pairing rate
    // limiter, which trusts forwarded IP headers ONLY from loopback
    // peers (the local tunnel proxy) and keys everyone else by their
    // real address.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// GET /.well-known/agent.json — Agent Card discovery.
async fn get_agent_card(State(state): State<A2aState>) -> Json<AgentCard> {
    let registry = state.agent_service.tool_registry();
    let card = agent_card::build_agent_card(&state.host, state.port, Some(registry));
    Json(card)
}

/// POST /a2a/v1 -- JSON-RPC 2.0 endpoint.
/// Returns JSON for most methods, SSE stream for `message/stream`.
async fn handle_jsonrpc(
    State(state): State<A2aState>,
    Extension(granted): Extension<GrantedScopes>,
    Extension(device): Extension<GrantedDevice>,
    Json(req): Json<JsonRpcRequest>,
) -> axum::response::Response {
    // An authenticated call is the definition of "this tunnel is in use", and
    // it is what keeps the idle reaper from stopping a tunnel somebody is
    // talking to (#2537).
    crate::remote::tunnel::note_traffic(&state.remote_state_dir);

    if req.jsonrpc != "2.0" {
        return (
            StatusCode::OK,
            Json(JsonRpcResponse::error(
                req.id,
                error_codes::INVALID_REQUEST,
                "Invalid JSON-RPC version, expected 2.0",
            )),
        )
            .into_response();
    }

    // Scope gate BEFORE any dispatch (and before the stream branch, so
    // message/stream is covered). Unknown methods fall through to the
    // dispatcher's MethodNotFound — credentials don't change that.
    if let Some(required) = scope_for_method(&req.method)
        && !allows(&granted.0, required)
    {
        return (
            StatusCode::OK,
            Json(JsonRpcResponse::error(
                req.id,
                error_codes::INSUFFICIENT_SCOPE,
                format!("insufficient scope: {required} required"),
            )),
        )
            .into_response();
    }

    // message/stream returns SSE instead of JSON
    if req.method == "message/stream" {
        return handle_stream(state, req).await;
    }

    // The remote shared-session surface. `session/attach` answers SSE, so it
    // branches before the JSON dispatcher; everything else is one call.
    if crate::remote::http::is_remote_method(&req.method) || req.method == "session/attach" {
        let Some(relay) = state.relay.clone() else {
            return (
                StatusCode::OK,
                Json(JsonRpcResponse::error(
                    req.id,
                    error_codes::METHOD_NOT_FOUND,
                    format!("Method not found: {}", req.method),
                )),
            )
                .into_response();
        };
        let device = device.0.clone();
        if req.method == "session/attach" {
            return handle_attach(relay, req, device).await;
        }
        if let Some(response) = crate::remote::http::dispatch(
            relay,
            req.id.clone(),
            &req.method,
            req.params.clone(),
            device.as_deref(),
        )
        .await
        {
            return (StatusCode::OK, Json(response)).into_response();
        }
    }

    let response = handler::dispatch(
        req,
        state.task_store,
        state.cancel_store,
        state.agent_service,
        state.service_context.clone(),
    )
    .await;
    (StatusCode::OK, Json(response)).into_response()
}

/// Handle `message/stream` -- returns an SSE stream of task updates.
async fn handle_stream(state: A2aState, req: JsonRpcRequest) -> axum::response::Response {
    match handler::stream::handle_stream_message(
        req.id,
        req.params,
        state.task_store,
        state.cancel_store,
        state.agent_service,
        state.service_context,
    )
    .await
    {
        Ok((id, rx)) => {
            let stream = stream::unfold((id, rx), |(id, mut rx)| async move {
                let event = rx.recv().await?;
                let result = serde_json::to_value(&event).unwrap_or_default();
                let rpc_response = JsonRpcResponse::success(id.clone(), result);
                let data = serde_json::to_string(&rpc_response).unwrap_or_default();
                let sse_event = Ok::<_, std::convert::Infallible>(sse::Event::default().data(data));
                Some((sse_event, (id, rx)))
            });
            Sse::new(stream).into_response()
        }
        Err(error_response) => (StatusCode::OK, Json(error_response)).into_response(),
    }
}

/// Handle `session/attach` -- returns an SSE stream of sequenced frames.
///
/// The first frames are whatever the client missed (from the ring buffer),
/// then the live subscription continues. A `resume_from` older than the ring
/// answers `RESUME_GAP` with `oldest_seq` so the client reloads history
/// rather than silently skipping events.
async fn handle_attach(
    relay: Arc<crate::remote::relay::RelayState>,
    req: JsonRpcRequest,
    device: Option<String>,
) -> axum::response::Response {
    use crate::remote::errors::RemoteError;

    let id = req.id.clone();
    let session_id = match req
        .params
        .get("session_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
    {
        Some(v) => v,
        None => {
            let err = RemoteError::ValidationError {
                field: "session_id".into(),
                reason: "required uuid".into(),
            };
            return (StatusCode::OK, Json(err.to_response(id))).into_response();
        }
    };
    let resume_from = req.params.get("resume_from").and_then(|v| v.as_u64());

    if let Err(e) = crate::remote::session_api::ensure_session(&relay, session_id).await {
        return (StatusCode::OK, Json(e.to_response(id))).into_response();
    }

    let device_id = device.unwrap_or_else(|| "anonymous".to_string());
    let (replay, sub) = match relay.attach(session_id, resume_from, &device_id) {
        Ok(v) => v,
        Err(e) => return (StatusCode::OK, Json(e.to_response(id))).into_response(),
    };

    // `Sse::new` wants a `TryStream<Ok = Event>`, so each frame is wrapped in
    // `Ok`; the unfold never fails, hence `Infallible`.
    let sse_stream = stream::unfold(
        (replay.into_iter(), sub.rx),
        |(mut replay, mut rx)| async move {
            if let Some(frame) = replay.next() {
                return Some((
                    Ok::<_, std::convert::Infallible>(frame_event(&frame)),
                    (replay, rx),
                ));
            }
            let frame = rx.recv().await?;
            Some((
                Ok::<_, std::convert::Infallible>(frame_event(&frame)),
                (replay, rx),
            ))
        },
    );
    Sse::new(sse_stream).into_response()
}

/// One sequence frame as an SSE event.
fn frame_event(frame: &crate::remote::seq::Frame) -> sse::Event {
    let body = serde_json::json!({
        "seq": frame.seq,
        "kind": frame.kind,
        "payload": frame.payload,
    });
    sse::Event::default().data(body.to_string())
}

/// GET /a2a/health — Health check. Public; the optional `routes`/`host_id`
/// block appears ONLY for a valid read-scoped bearer when an api_key is
/// configured (announcement privacy invariant — see `routes_http`).
async fn health_check(
    State(state): State<A2aState>,
    headers: axum::http::HeaderMap,
) -> Json<serde_json::Value> {
    let mut body = serde_json::json!({
        "status": "ok",
        "version": crate::VERSION,
        "protocol": "A2A",
        "protocol_version": "1.0",
        "provider": "OpenCrabs Community"
    });
    if state.api_key.is_some()
        && credential_scopes(&state, bearer_from_headers(&headers))
            .is_some_and(|s| allows(&s, crate::remote::scopes::SCOPE_READ))
    {
        match routes_http::announced_routes(&state) {
            Ok((host_id, routes)) => {
                body["host_id"] = serde_json::json!(host_id);
                body["routes"] = serde_json::to_value(&routes).unwrap_or_default();
            }
            Err(e) => tracing::warn!("health route announcement failed: {e:#}"),
        }
    }
    Json(body)
}
