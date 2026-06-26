use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Nullable, Text, Timestamptz};
use diesel::PgConnection;

use crate::service::siem::geoip::GeoIp;

const ACTIVE_WINDOW_MINS: i64 = 15;

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
    let label = if l.contains("console.amazonaws") || l.contains("aws internal") || l.contains("signin.amazonaws") {
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

/// Derive sessions from the trailing `window_days` of CloudTrail auth events.
/// Returns the number of session rows upserted.
pub fn derive(conn: &mut PgConnection, geoip: &GeoIp, window_days: i64) -> anyhow::Result<usize> {
    let floor = Utc::now() - Duration::days(window_days.max(1));

    let candidates: Vec<SessionCandidate> = diesel::sql_query(
        "SELECT \
           c.principal_name AS principal, \
           c.source_ip AS source_ip, \
           date_trunc('day', c.event_time) AS day, \
           min(c.event_time) AS started_at, \
           max(c.event_time) AS last_seen_at, \
           count(*) AS event_count, \
           (array_agg(c.user_agent ORDER BY c.event_time DESC))[1] AS user_agent, \
           aa.actor_id AS actor_id \
         FROM cloudtrail_events c \
         LEFT JOIN actor_aliases aa ON aa.alias = COALESCE(c.principal_name, c.principal_arn) \
         WHERE c.event_name IN ('ConsoleLogin','AssumeRole','AssumeRoleWithSAML','AssumeRoleWithWebIdentity') \
           AND c.event_time >= $1 \
           AND c.principal_name IS NOT NULL \
         GROUP BY c.principal_name, c.source_ip, date_trunc('day', c.event_time), aa.actor_id",
    )
    .bind::<Timestamptz, _>(floor)
    .load(conn)
    .context("load session candidates")?;

    let now = Utc::now();
    let active_floor = now - Duration::minutes(ACTIVE_WINDOW_MINS);
    let mut upserted = 0usize;

    conn.transaction::<_, anyhow::Error, _>(|conn| {
        for c in &candidates {
            let ip = c.source_ip.clone().unwrap_or_else(|| "-".to_string());
            let session_key = format!("{}|{}|{}", c.principal, ip, c.day.format("%Y-%m-%d"));
            let device = device_of(c.user_agent.as_deref());
            let location = c.source_ip.as_deref().and_then(|i| geoip.lookup(i));
            let status = if c.last_seen_at >= active_floor { "active" } else { "closed" };

            diesel::sql_query(
                "INSERT INTO sessions \
                   (session_key, actor_id, source, device, source_ip, location, started_at, last_seen_at, event_count, status) \
                 VALUES ($1, $2, 'cloudtrail', $3, $4, $5, $6, $7, $8, $9) \
                 ON CONFLICT (session_key) DO UPDATE SET \
                   actor_id     = COALESCE(EXCLUDED.actor_id, sessions.actor_id), \
                   device       = COALESCE(EXCLUDED.device, sessions.device), \
                   location     = COALESCE(EXCLUDED.location, sessions.location), \
                   started_at   = LEAST(EXCLUDED.started_at, sessions.started_at), \
                   last_seen_at = GREATEST(EXCLUDED.last_seen_at, sessions.last_seen_at), \
                   event_count  = EXCLUDED.event_count, \
                   status       = CASE WHEN sessions.status = 'flagged' THEN 'flagged' ELSE EXCLUDED.status END",
            )
            .bind::<Text, _>(&session_key)
            .bind::<Nullable<Text>, _>(c.actor_id.as_ref())
            .bind::<Nullable<Text>, _>(device)
            .bind::<Nullable<Text>, _>(c.source_ip.as_ref())
            .bind::<Nullable<Text>, _>(location)
            .bind::<Timestamptz, _>(c.started_at)
            .bind::<Timestamptz, _>(c.last_seen_at)
            .bind::<BigInt, _>(c.event_count)
            .bind::<Text, _>(status)
            .execute(conn)
            .context("upsert session")?;
            upserted += 1;
        }
        Ok(())
    })?;

    Ok(upserted)
}
