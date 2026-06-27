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
struct Login {
    #[diesel(sql_type = Text)]
    actor_id: String,
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

    // Resolved logins only (actor known, ip present), ordered for pairing.
    let logins: Vec<Login> = diesel::sql_query(
        "SELECT aa.actor_id AS actor_id, c.source_ip AS source_ip, c.event_time AS event_time \
         FROM cloudtrail_events c JOIN actor_aliases aa ON aa.alias = COALESCE(c.principal_name, c.principal_arn) \
         WHERE c.event_name IN ('ConsoleLogin','AssumeRole','AssumeRoleWithSAML','AssumeRoleWithWebIdentity') \
           AND c.source_ip IS NOT NULL AND c.event_time >= $1 \
         ORDER BY aa.actor_id, c.event_time ASC",
    )
    .bind::<Timestamptz, _>(floor)
    .load(conn)
    .context("load travel logins")?;

    // Cache geo lookups; many events share an IP.
    let mut geo_cache: HashMap<String, Option<GeoPoint>> = HashMap::new();
    let mut geo = |ip: &str| -> Option<GeoPoint> {
        geo_cache
            .entry(ip.to_string())
            .or_insert_with(|| geoip.lookup_geo(ip))
            .clone()
    };

    // Per actor, walk consecutive *distinct* geolocated points.
    let mut pairs: Vec<TravelPair> = Vec::new();
    let mut cur_actor: Option<&str> = None;
    let mut last: Option<(String, GeoPoint, DateTime<Utc>)> = None; // (ip, point, time)

    for l in &logins {
        if cur_actor != Some(l.actor_id.as_str()) {
            cur_actor = Some(l.actor_id.as_str());
            last = None;
        }
        let Some(point) = geo(&l.source_ip) else {
            continue;
        };
        if let Some((prev_ip, prev_point, prev_time)) = &last {
            if *prev_ip != l.source_ip {
                let km = haversine_km(prev_point, &point);
                let hours = (l.event_time - *prev_time).num_seconds().max(1) as f64 / 3600.0;
                let kmh = km / hours;
                if kmh > siem.impossible_travel_kmh && km > 100.0 {
                    pairs.push(TravelPair {
                        actor_id: l.actor_id.clone(),
                        from_ip: prev_ip.clone(),
                        to_ip: l.source_ip.clone(),
                        from_loc: prev_point.label.clone(),
                        to_loc: point.label.clone(),
                        km,
                        hours,
                        kmh,
                        at: l.event_time,
                    });
                }
            }
        }
        last = Some((l.source_ip.clone(), point, l.event_time));
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
