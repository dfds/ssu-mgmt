use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Router;
use serde_json::{json, Value};
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tower_layer::Layer;

use crate::api::WebSharedState;
use crate::db::DbPool;
use crate::misc::config::load_conf;
use crate::service::ingest::progress_subscribe;

use super::overview;

/// Debounce window: a SIEM pass or a CloudTrail commit can write several
/// watermarks in a burst; collapse them into one snapshot push.
const DEBOUNCE: Duration = Duration::from_millis(300);
/// Keep-alive ping cadence (matches the Go reference's 30s).
const PING_EVERY: Duration = Duration::from_secs(30);
/// WS close code for a failed auth — the client uses this to stop reconnecting
/// (RFC 6455 1008 "policy violation").
const CLOSE_UNAUTHORIZED: u16 = 1008;

pub fn routes(state: WebSharedState) -> Router {
    Router::new()
        .route("/ws", axum::routing::get(ws_handler))
        .with_state(state)
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<WebSharedState>, headers: HeaderMap) -> Response {
    let conf = load_conf().unwrap();

    // Pull the bearer token out of the WS subprotocol header (`bearer, <jwt>`).
    let token = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| {
            let mut parts = raw.split(',').map(|s| s.trim());
            match parts.next() {
                Some("bearer") => parts.next().filter(|t| !t.is_empty()).map(|t| t.to_owned()),
                _ => None,
            }
        });

    let authed = if conf.api_enable_auth {
        match token.as_deref() {
            Some(t) => validate(&state, t).await,
            None => false,
        }
    } else {
        // Dev parity with `role_check`/`auth_oauth`: when auth is off, accept.
        true
    };

    let pool = state.db_pool.clone();
    ws.protocols(["bearer"])
        .on_upgrade(move |socket| run(socket, pool, authed))
}

async fn validate(state: &WebSharedState, token: &str) -> bool {
    let auth_svc = state.jwt_validator.layer(Value::default()).auths.first().unwrap().clone();
    match auth_svc.check_auth(token).await {
        Ok(token_data) => token_data
            .claims
            .get("roles")
            .and_then(|r| r.as_array())
            .map(|arr| arr.iter().any(|v| v.as_str() == Some("ce.cloudengineer")))
            .unwrap_or(false),
        Err(_) => false,
    }
}

async fn run(mut socket: WebSocket, pool: DbPool, authed: bool) {
    if !authed {
        let _ = socket
            .send(Message::Close(Some(CloseFrame {
                code: CLOSE_UNAUTHORIZED,
                reason: "unauthorized".into(),
            })))
            .await;
        return;
    }

    // Subscribe before the initial snapshot so no signal is missed in between.
    let mut rx = progress_subscribe();

    // Initial full snapshot so a fresh console paints immediately.
    if push_snapshots(&mut socket, &pool).await.is_err() {
        return;
    }

    let mut ping = tokio::time::interval(PING_EVERY);
    ping.tick().await; // consume the immediate first tick

    loop {
        let recv = async {
            match rx.as_mut() {
                Some(r) => r.recv().await,
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            signal = recv => {
                match signal {
                    Ok(_) | Err(RecvError::Lagged(_)) => {
                        // Debounce + drain the backlog into a single snapshot push.
                        tokio::time::sleep(DEBOUNCE).await;
                        if let Some(r) = rx.as_mut() {
                            loop {
                                match r.try_recv() {
                                    Ok(_) | Err(TryRecvError::Lagged(_)) => continue,
                                    Err(_) => break, // Empty or Closed
                                }
                            }
                        }
                        if push_snapshots(&mut socket, &pool).await.is_err() {
                            break;
                        }
                    }
                    Err(RecvError::Closed) => break,
                }
            }
            _ = ping.tick() => {
                if socket.send(Message::Ping(Vec::new())).await.is_err() {
                    break;
                }
            }
            inbound = socket.recv() => {
                match inbound {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    Some(Ok(_)) => {} // pong / stray frame — ignore
                }
            }
        }
    }
}

async fn push_snapshots(socket: &mut WebSocket, pool: &DbPool) -> Result<(), ()> {
    let pool = pool.clone();
    let snaps = tokio::task::spawn_blocking(move || -> anyhow::Result<(Value, Value, Value)> {
        let mut conn = pool.get()?;
        let ingest = serde_json::to_value(overview::load_ingest_health(&mut conn)?)?;
        let kpis = overview::load_kpis(&mut conn)?;
        let alerts = serde_json::to_value(overview::load_overview_alerts(&mut conn, 50)?)?;
        Ok((ingest, kpis, alerts))
    })
    .await;

    let (ingest, kpis, alerts) = match snaps {
        Ok(Ok(v)) => v,
        // DB hiccup or join error — skip this push, keep the socket alive.
        _ => return Ok(()),
    };

    for (ty, payload) in [("ingest_health", ingest), ("kpis", kpis), ("alerts", alerts)] {
        let frame = json!({ "type": ty, "payload": payload }).to_string();
        if socket.send(Message::Text(frame)).await.is_err() {
            return Err(());
        }
    }
    Ok(())
}
