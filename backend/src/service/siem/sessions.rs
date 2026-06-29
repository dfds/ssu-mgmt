use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use diesel::sql_types::{Array, BigInt, Nullable, Text, Timestamptz};
use diesel::PgConnection;

use crate::service::ingest::get_watermark;
use crate::service::siem::geoip::GeoIp;

const ACTIVE_WINDOW_MINS: i64 = 15;

const SESSIONS_WATERMARK_SOURCE: &str = "siem_sessions";
const SESSIONS_SAFETY_MARGIN_MINS: i64 = 15;
const MAX_SESSIONS_STEP_HOURS: i64 = 3;
const SESSIONS_UPSERT_CHUNK: usize = 1000;

/// A single derived session row, ready to upsert.
struct SessionUpsert {
    session_key: String,
    actor_id: Option<String>,
    device: Option<String>,
    source_ip: Option<String>,
    location: Option<String>,
    started_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    event_count: i64,
    status: String,
}

#[derive(QueryableByName)]
struct SessionCandidate {
    #[diesel(sql_type = Text)]
    principal: String,
    #[diesel(sql_type = Nullable<Text>)]
    source_ip: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    day: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    started_at: DateTime<Utc>,
    #[diesel(sql_type = Timestamptz)]
    last_seen_at: DateTime<Utc>,
    #[diesel(sql_type = BigInt)]
    event_count: i64,
    #[diesel(sql_type = Nullable<Text>)]
    user_agent: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    actor_id: Option<String>,
}

/// Best-effort device label from a CloudTrail user agent.
fn device_of(ua: Option<&str>) -> Option<String> {
    let ua = ua?;
    let l = ua.to_lowercase();
    let label = if l.contains("console.amazonaws")
        || l.contains("aws internal")
        || l.contains("signin.amazonaws")
    {
        "AWS Console"
    } else if l.contains("aws-cli") {
        "AWS CLI"
    } else if l.contains("boto") {
        "AWS SDK (boto)"
    } else if l.contains("terraform") {
        "Terraform"
    } else if l.contains("cloudformation") {
        "CloudFormation"
    } else {
        return Some(ua.chars().take(60).collect());
    };
    Some(label.to_string())
}

pub fn derive(conn: &mut PgConnection, geoip: &GeoIp, window_days: i64) -> anyhow::Result<usize> {
    let now = Utc::now();
    let event_floor = now - Duration::days(window_days.max(1));
    let active_floor = now - Duration::minutes(ACTIVE_WINDOW_MINS);
    let target = now - Duration::minutes(SESSIONS_SAFETY_MARGIN_MINS);

    let w = get_watermark(conn, SESSIONS_WATERMARK_SOURCE)
        .context("read sessions watermark")?
        .and_then(|wm| wm.last_event_at)
        .unwrap_or(target);
    let boundary = target.min(w + Duration::hours(MAX_SESSIONS_STEP_HOURS));

    let candidates: Vec<SessionCandidate> = diesel::sql_query(
        "SELECT \
           c.principal_name AS principal, \
           c.source_ip AS source_ip, \
           date_trunc('day', c.event_time) AS day, \
           min(c.event_time) AS started_at, \
           max(c.event_time) AS last_seen_at, \
           count(*) AS event_count, \
           (array_agg(c.user_agent ORDER BY c.event_time DESC))[1] AS user_agent, \
           min(aa.actor_id) AS actor_id \
         FROM cloudtrail_events c \
         LEFT JOIN actor_aliases aa ON aa.alias = COALESCE(c.principal_name, c.principal_arn) \
         WHERE c.event_name IN ('ConsoleLogin','AssumeRole','AssumeRoleWithSAML','AssumeRoleWithWebIdentity') \
           AND c.created_at > $1 AND c.created_at <= $2 \
           AND c.event_time >= $3 \
           AND c.principal_name IS NOT NULL \
         GROUP BY c.principal_name, c.source_ip, date_trunc('day', c.event_time)",
    )
    .bind::<Timestamptz, _>(w)
    .bind::<Timestamptz, _>(boundary)
    .bind::<Timestamptz, _>(event_floor)
    .load(conn)
    .context("load session candidates")?;

    let rows: Vec<SessionUpsert> = candidates
        .iter()
        .map(|c| {
            let ip = c.source_ip.clone().unwrap_or_else(|| "-".to_string());
            SessionUpsert {
                session_key: format!("{}|{}|{}", c.principal, ip, c.day.format("%Y-%m-%d")),
                actor_id: c.actor_id.clone(),
                device: device_of(c.user_agent.as_deref()),
                source_ip: c.source_ip.clone(),
                location: c.source_ip.as_deref().and_then(|i| geoip.lookup(i)),
                started_at: c.started_at,
                last_seen_at: c.last_seen_at,
                event_count: c.event_count,
                status: if c.last_seen_at >= active_floor {
                    "active"
                } else {
                    "closed"
                }
                .to_string(),
            }
        })
        .collect();

    let upserted = rows.len();

    conn.transaction::<_, anyhow::Error, _>(|conn| {
        for chunk in rows.chunks(SESSIONS_UPSERT_CHUNK) {
            upsert_chunk(conn, chunk)?;
        }

        diesel::sql_query(
            "UPDATE sessions SET status = 'closed' \
             WHERE status = 'active' AND last_seen_at < $1",
        )
        .bind::<Timestamptz, _>(active_floor)
        .execute(conn)
        .context("age out stale sessions")?;

        diesel::sql_query(
            "INSERT INTO ingest_watermarks \
               (source, last_event_at, last_run_at, objects_scanned, events_applied) \
             VALUES ($1, $2, now(), 0, 0) \
             ON CONFLICT (source) DO UPDATE SET \
               last_event_at = GREATEST(EXCLUDED.last_event_at, ingest_watermarks.last_event_at), \
               last_run_at   = now()",
        )
        .bind::<Text, _>(SESSIONS_WATERMARK_SOURCE)
        .bind::<Timestamptz, _>(boundary)
        .execute(conn)
        .context("advance sessions watermark")?;
        Ok(())
    })?;

    Ok(upserted)
}

fn upsert_chunk(conn: &mut PgConnection, chunk: &[SessionUpsert]) -> anyhow::Result<()> {
    if chunk.is_empty() {
        return Ok(());
    }
    let keys: Vec<&str> = chunk.iter().map(|r| r.session_key.as_str()).collect();
    let actor_ids: Vec<Option<&str>> = chunk.iter().map(|r| r.actor_id.as_deref()).collect();
    let devices: Vec<Option<&str>> = chunk.iter().map(|r| r.device.as_deref()).collect();
    let ips: Vec<Option<&str>> = chunk.iter().map(|r| r.source_ip.as_deref()).collect();
    let locations: Vec<Option<&str>> = chunk.iter().map(|r| r.location.as_deref()).collect();
    let starts: Vec<DateTime<Utc>> = chunk.iter().map(|r| r.started_at).collect();
    let lasts: Vec<DateTime<Utc>> = chunk.iter().map(|r| r.last_seen_at).collect();
    let counts: Vec<i64> = chunk.iter().map(|r| r.event_count).collect();
    let statuses: Vec<&str> = chunk.iter().map(|r| r.status.as_str()).collect();

    diesel::sql_query(
        "INSERT INTO sessions \
           (session_key, actor_id, source, device, source_ip, location, started_at, last_seen_at, event_count, status) \
         SELECT k, a, 'cloudtrail', d, ip, loc, st, ls, ec, status \
         FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], \
                     $6::timestamptz[], $7::timestamptz[], $8::bigint[], $9::text[]) \
              AS t(k, a, d, ip, loc, st, ls, ec, status) \
         ON CONFLICT (session_key) DO UPDATE SET \
           actor_id     = COALESCE(EXCLUDED.actor_id, sessions.actor_id), \
           device       = COALESCE(EXCLUDED.device, sessions.device), \
           location     = COALESCE(EXCLUDED.location, sessions.location), \
           started_at   = LEAST(EXCLUDED.started_at, sessions.started_at), \
           last_seen_at = GREATEST(EXCLUDED.last_seen_at, sessions.last_seen_at), \
           event_count  = sessions.event_count + EXCLUDED.event_count, \
           status       = CASE WHEN sessions.status = 'flagged' THEN 'flagged' ELSE EXCLUDED.status END",
    )
    .bind::<Array<Text>, _>(keys)
    .bind::<Array<Nullable<Text>>, _>(actor_ids)
    .bind::<Array<Nullable<Text>>, _>(devices)
    .bind::<Array<Nullable<Text>>, _>(ips)
    .bind::<Array<Nullable<Text>>, _>(locations)
    .bind::<Array<Timestamptz>, _>(starts)
    .bind::<Array<Timestamptz>, _>(lasts)
    .bind::<Array<BigInt>, _>(counts)
    .bind::<Array<Text>, _>(statuses)
    .execute(conn)
    .context("batch upsert sessions")?;
    Ok(())
}
