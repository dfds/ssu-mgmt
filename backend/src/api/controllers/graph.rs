use std::collections::{BTreeMap, BTreeSet};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use axum_extra::extract::Query;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel::sql_types::{Array, BigInt, Nullable, Text, Timestamptz};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db::DbPool;

const NODE_CAP: usize = 150;

pub fn routes(pool: DbPool) -> Router {
    Router::new().route("/", axum::routing::get(graph_handler)).with_state(pool)
}

#[derive(Deserialize)]
pub struct GraphParams {
    pub mode: Option<String>,
    pub actor: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(QueryableByName)]
struct EdgeRow {
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = Text)]
    source: String,
    #[diesel(sql_type = BigInt)]
    weight: i64,
    #[diesel(sql_type = BigInt)]
    failures: i64,
}

#[derive(QueryableByName)]
struct ActorMeta {
    #[diesel(sql_type = Text)]
    id: String,
    #[diesel(sql_type = Text)]
    label: String,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = diesel::sql_types::Integer)]
    score: i32,
}

#[derive(QueryableByName)]
struct IpRow {
    #[diesel(sql_type = Nullable<Text>)]
    ip: Option<String>,
    #[diesel(sql_type = BigInt)]
    weight: i64,
}

#[derive(QueryableByName)]
struct PeerRow {
    #[diesel(sql_type = Nullable<Text>)]
    ip: Option<String>,
    #[diesel(sql_type = Text)]
    peer: String,
    #[diesel(sql_type = BigInt)]
    weight: i64,
}

#[derive(Serialize)]
struct Node {
    id: String,
    #[serde(rename = "type")]
    node_type: String,
    label: String,
    risk: i32,
}

#[derive(Serialize)]
struct Edge {
    from: String,
    to: String,
    kind: String,
    weight: i64,
    failure: bool,
}

async fn graph_handler(State(pool): State<DbPool>, Query(params): Query<GraphParams>) -> Response {
    let mode = params.mode.clone().unwrap_or_else(|| "surface".to_string());
    let actor = params.actor.clone();

    if mode == "entity" && actor.as_deref().unwrap_or("").is_empty() {
        return (StatusCode::BAD_REQUEST, "entity mode requires ?actor=").into_response();
    }

    let span = tracing::info_span!("db.query", otel.kind = "client", db.system = "postgresql", op ="graph.aggregate");
    let res = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
        let _g = span.enter();
        let mut conn = pool.get()?;
        let floor = Utc::now() - Duration::days(7);

        // --- actor↔source edges, scoped by mode -----------------------------
        let edges: Vec<EdgeRow> = match mode.as_str() {
            "entity" => diesel::sql_query(
                "SELECT aa.actor_id AS actor_id, e.source AS source, count(*) AS weight, \
                        count(*) FILTER (WHERE e.status = 'failure') AS failures \
                 FROM ssumgmt_events e JOIN actor_aliases aa ON aa.alias = e.actor \
                 WHERE aa.actor_id = $1 AND e.ts >= $2 \
                 GROUP BY aa.actor_id, e.source",
            )
            .bind::<Text, _>(actor.as_deref().unwrap_or(""))
            .bind::<Timestamptz, _>(floor)
            .load(&mut conn)?,
            "investigate" => diesel::sql_query(
                "SELECT aa.actor_id AS actor_id, e.source AS source, count(*) AS weight, \
                        count(*) FILTER (WHERE e.status = 'failure') AS failures \
                 FROM ssumgmt_events e JOIN actor_aliases aa ON aa.alias = e.actor \
                 WHERE e.ts >= $2 AND ($1 = '' OR aa.actor_id ILIKE '%' || $1 || '%') \
                 GROUP BY aa.actor_id, e.source \
                 ORDER BY weight DESC LIMIT 400",
            )
            .bind::<Text, _>(actor.as_deref().unwrap_or(""))
            .bind::<Timestamptz, _>(floor)
            .load(&mut conn)?,
            // surface (default): top actors by risk then activity ↔ sources.
            _ => diesel::sql_query(
                "WITH top_actors AS ( \
                    SELECT aa.actor_id AS actor_id, count(*) AS activity \
                    FROM ssumgmt_events e JOIN actor_aliases aa ON aa.alias = e.actor \
                    WHERE e.ts >= $1 GROUP BY aa.actor_id \
                 ), chosen AS ( \
                    SELECT ta.actor_id FROM top_actors ta LEFT JOIN risk_scores r ON r.actor_id = ta.actor_id \
                    ORDER BY COALESCE(r.score, 0) DESC, ta.activity DESC LIMIT 40 \
                 ) \
                 SELECT aa.actor_id AS actor_id, e.source AS source, count(*) AS weight, \
                        count(*) FILTER (WHERE e.status = 'failure') AS failures \
                 FROM ssumgmt_events e JOIN actor_aliases aa ON aa.alias = e.actor \
                 JOIN chosen c ON c.actor_id = aa.actor_id \
                 WHERE e.ts >= $1 \
                 GROUP BY aa.actor_id, e.source",
            )
            .bind::<Timestamptz, _>(floor)
            .load(&mut conn)?,
        };

        let mut nodes: BTreeMap<String, Node> = BTreeMap::new();
        let mut out_edges: Vec<Edge> = Vec::new();
        let mut actor_ids: BTreeSet<String> = BTreeSet::new();

        // Source nodes + actor↔source edges (respecting the cap by actor weight).
        let mut actor_weight: BTreeMap<String, i64> = BTreeMap::new();
        for e in &edges {
            *actor_weight.entry(e.actor_id.clone()).or_insert(0) += e.weight;
        }
        // Choose the heaviest actors first if we exceed the cap.
        let mut ranked: Vec<(String, i64)> = actor_weight.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1));
        let total_actors = ranked.len();
        let keep: BTreeSet<String> = ranked.into_iter().take(NODE_CAP.saturating_sub(16)).map(|(a, _)| a).collect();

        for e in &edges {
            if !keep.contains(&e.actor_id) {
                continue;
            }
            actor_ids.insert(e.actor_id.clone());
            let src_id = format!("source:{}", e.source);
            nodes.entry(src_id.clone()).or_insert_with(|| Node {
                id: src_id.clone(),
                node_type: "source".to_string(),
                label: e.source.clone(),
                risk: 0,
            });
            out_edges.push(Edge {
                from: format!("actor:{}", e.actor_id),
                to: src_id,
                kind: "activity".to_string(),
                weight: e.weight,
                failure: e.failures > 0,
            });
        }

        // --- entity mode: add IP nodes + peer actors (shared infrastructure) --
        if mode == "entity" {
            let a = actor.as_deref().unwrap_or("");
            let ips: Vec<IpRow> = diesel::sql_query(
                "SELECT e.source_ip AS ip, count(*) AS weight \
                 FROM ssumgmt_events e JOIN actor_aliases aa ON aa.alias = e.actor \
                 WHERE aa.actor_id = $1 AND e.source_ip IS NOT NULL AND e.ts >= $2 \
                 GROUP BY e.source_ip ORDER BY weight DESC LIMIT 10",
            )
            .bind::<Text, _>(a)
            .bind::<Timestamptz, _>(floor)
            .load(&mut conn)?;

            let ip_list: Vec<String> = ips.iter().filter_map(|r| r.ip.clone()).collect();
            for r in &ips {
                if let Some(ip) = &r.ip {
                    let ip_id = format!("ip:{}", ip);
                    nodes.entry(ip_id.clone()).or_insert_with(|| Node {
                        id: ip_id.clone(),
                        node_type: "ip".to_string(),
                        label: ip.clone(),
                        risk: 0,
                    });
                    out_edges.push(Edge {
                        from: format!("actor:{}", a),
                        to: ip_id,
                        kind: "network".to_string(),
                        weight: r.weight,
                        failure: false,
                    });
                }
            }

            if !ip_list.is_empty() {
                let peers: Vec<PeerRow> = diesel::sql_query(
                    "SELECT e.source_ip AS ip, aa.actor_id AS peer, count(*) AS weight \
                     FROM ssumgmt_events e JOIN actor_aliases aa ON aa.alias = e.actor \
                     WHERE e.source_ip = ANY($1) AND aa.actor_id <> $2 AND e.ts >= $3 \
                     GROUP BY e.source_ip, aa.actor_id ORDER BY weight DESC LIMIT 50",
                )
                .bind::<Array<Text>, _>(&ip_list)
                .bind::<Text, _>(a)
                .bind::<Timestamptz, _>(floor)
                .load(&mut conn)?;
                for p in &peers {
                    if let Some(ip) = &p.ip {
                        actor_ids.insert(p.peer.clone());
                        out_edges.push(Edge {
                            from: format!("ip:{}", ip),
                            to: format!("actor:{}", p.peer),
                            kind: "shared-ip".to_string(),
                            weight: p.weight,
                            failure: false,
                        });
                    }
                }
            }
        }

        // --- actor node metadata (label + risk) -----------------------------
        let id_vec: Vec<String> = actor_ids.iter().cloned().collect();
        if !id_vec.is_empty() {
            let metas: Vec<ActorMeta> = diesel::sql_query(
                "SELECT a.id AS id, COALESCE(a.display_name, a.id) AS label, a.kind AS kind, COALESCE(r.score, 0) AS score \
                 FROM actors a LEFT JOIN risk_scores r ON r.actor_id = a.id WHERE a.id = ANY($1)",
            )
            .bind::<Array<Text>, _>(&id_vec)
            .load(&mut conn)?;
            for m in metas {
                let node_id = format!("actor:{}", m.id);
                nodes.insert(node_id.clone(), Node {
                    id: node_id,
                    node_type: "actor".to_string(),
                    label: m.label,
                    risk: m.score,
                });
            }
            // Any actor referenced by an edge but missing an actors row (unlikely)
            // still gets a minimal node so the edge isn't dangling.
            for id in &id_vec {
                let node_id = format!("actor:{}", id);
                nodes.entry(node_id.clone()).or_insert_with(|| Node {
                    id: node_id.clone(),
                    node_type: "actor".to_string(),
                    label: id.clone(),
                    risk: 0,
                });
            }
        }

        let node_vec: Vec<&Node> = nodes.values().collect();
        Ok(json!({
            "nodes": node_vec,
            "edges": out_edges,
            "shownOf": { "shown": actor_ids.len(), "total": total_actors },
            "mode": mode,
        }))
    })
    .await;

    match res {
        Ok(Ok(v)) => Json(v).into_response(),
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {}", e)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("task join error: {}", e)).into_response(),
    }
}
