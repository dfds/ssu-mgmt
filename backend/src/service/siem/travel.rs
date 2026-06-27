use std::collections::HashMap;

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use diesel::prelude::*;
use diesel::sql_types::{Text, Timestamptz};
use diesel::PgConnection;
use log::debug;
use serde_json::json;

use crate::misc::config::SiemConfig;
use crate::service::siem::geoip::{haversine_km, GeoIp, GeoPoint};

#[derive(QueryableByName)]
struct Transition {
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = Text)]
    prev_ip: String,
    #[diesel(sql_type = Timestamptz)]
    prev_time: DateTime<Utc>,
    #[diesel(sql_type = Text)]
    source_ip: String,
    #[diesel(sql_type = Timestamptz)]
    event_time: DateTime<Utc>,
}

/// Detect impossible travel across logins in the trailing window. Returns the
/// number of alert rows touched. A no-op (returns 0) when GeoIP is disabled.
pub fn detect(conn: &mut PgConnection, geoip: &GeoIp, siem: &SiemConfig) -> anyhow::Result<usize> {
    if !geoip.enabled() {
        debug!("impossible_travel: geoip disabled — skipping");
        return Ok(0);
    }
    let floor = Utc::now() - Duration::days(siem.window_days.max(1));

    let transitions: Vec<Transition> = diesel::sql_query(
        "SELECT actor_id, prev_ip, prev_time, source_ip, event_time FROM ( \
           SELECT aa.actor_id AS actor_id, c.source_ip AS source_ip, c.event_time AS event_time, \
                  lag(c.source_ip) OVER w AS prev_ip, \
                  lag(c.event_time) OVER w AS prev_time \
           FROM cloudtrail_events c \
           JOIN actor_aliases aa ON aa.alias = COALESCE(c.principal_name, c.principal_arn) \
           WHERE c.event_name IN ('ConsoleLogin','AssumeRole','AssumeRoleWithSAML','AssumeRoleWithWebIdentity') \
             AND c.source_ip IS NOT NULL AND c.event_time >= $1 \
           WINDOW w AS (PARTITION BY aa.actor_id ORDER BY c.event_time ASC) \
         ) t \
         WHERE prev_ip IS NOT NULL AND prev_ip IS DISTINCT FROM source_ip",
    )
    .bind::<Timestamptz, _>(floor)
    .load(conn)
    .context("load travel transitions")?;

    // Cache geo lookups; transitions reuse the same handful of IPs.
    let mut geo_cache: HashMap<String, Option<GeoPoint>> = HashMap::new();
    let mut geo = |ip: &str| -> Option<GeoPoint> {
        geo_cache
            .entry(ip.to_string())
            .or_insert_with(|| geoip.lookup_geo(ip))
            .clone()
    };
    
    let mut pairs: Vec<TravelPair> = Vec::new();
    for t in &transitions {
        let from = geo(&t.prev_ip);
        let to = geo(&t.source_ip);
        let (Some(from_point), Some(to_point)) = (from, to) else {
            continue;
        };
        let km = haversine_km(&from_point, &to_point);
        let hours = (t.event_time - t.prev_time).num_seconds().max(1) as f64 / 3600.0;
        let kmh = km / hours;
        if kmh > siem.impossible_travel_kmh && km > 100.0 {
            pairs.push(TravelPair {
                actor_id: t.actor_id.clone(),
                from_ip: t.prev_ip.clone(),
                to_ip: t.source_ip.clone(),
                from_loc: from_point.label.clone(),
                to_loc: to_point.label.clone(),
                km,
                hours,
                kmh,
                at: t.event_time,
            });
        }
    }

    let mut touched = 0usize;
    conn.transaction::<_, anyhow::Error, _>(|conn| {
        for p in &pairs {
            let fingerprint = format!(
                "impossible_travel:{}:{}:{}->{}",
                p.actor_id,
                p.at.format("%Y-%m-%d"),
                p.from_ip,
                p.to_ip
            );
            let description = format!(
                "{} appeared in {} then {} ({} km in {:.1}h ≈ {} km/h)",
                p.actor_id,
                p.from_loc,
                p.to_loc,
                p.km.round() as i64,
                p.hours,
                p.kmh.round() as i64
            );
            let evidence = json!({
                "from_ip": p.from_ip, "to_ip": p.to_ip,
                "from": p.from_loc, "to": p.to_loc,
                "km": (p.km * 10.0).round() / 10.0, "hours": (p.hours * 100.0).round() / 100.0,
                "kmh": p.kmh.round(),
            });
            touched += diesel::sql_query(
                "INSERT INTO alerts (fingerprint, rule_id, severity, title, description, actor_id, source, first_seen, last_seen, event_count, status, evidence, updated_at) \
                 VALUES ($1, 'impossible_travel', 'medium', 'Impossible travel', $2, $3, 'cloudtrail', $4, $4, 1, 'open', $5, now()) \
                 ON CONFLICT (fingerprint) DO UPDATE SET \
                   last_seen = GREATEST(alerts.last_seen, EXCLUDED.last_seen), description = EXCLUDED.description, \
                   evidence = EXCLUDED.evidence, \
                   status = CASE WHEN alerts.status = 'resolved' AND EXCLUDED.last_seen > COALESCE(alerts.resolved_at, alerts.last_seen) THEN 'open' ELSE alerts.status END, \
                   updated_at = now()",
            )
            .bind::<Text, _>(&fingerprint)
            .bind::<Text, _>(&description)
            .bind::<Text, _>(&p.actor_id)
            .bind::<Timestamptz, _>(p.at)
            .bind::<diesel::sql_types::Jsonb, _>(evidence)
            .execute(conn)
            .context("upsert impossible_travel alert")?;
        }
        Ok(())
    })?;

    Ok(touched)
}

struct TravelPair {
    actor_id: String,
    from_ip: String,
    to_ip: String,
    from_loc: String,
    to_loc: String,
    km: f64,
    hours: f64,
    kmh: f64,
    at: DateTime<Utc>,
}
