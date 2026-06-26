use anyhow::Context;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Double, Text, Timestamptz};
use diesel::PgConnection;
use serde_json::json;

use crate::misc::config::{RiskConfig, SiemConfig};

#[derive(QueryableByName)]
struct Factors {
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = BigInt)]
    failed_auth: i64,
    #[diesel(sql_type = BigInt)]
    priv_grants: i64,
    #[diesel(sql_type = Double)]
    off_hours_ratio: f64,
    #[diesel(sql_type = BigInt)]
    dormant: i64,
    #[diesel(sql_type = BigInt)]
    flagged_sessions: i64,
    #[diesel(sql_type = BigInt)]
    source_diversity: i64,
    #[diesel(sql_type = BigInt)]
    anomalies: i64,
}

fn label_of(score: i32) -> &'static str {
    match score {
        s if s >= 80 => "critical",
        s if s >= 60 => "high",
        s if s >= 30 => "medium",
        _ => "low",
    }
}

/// Recompute and store every actor's risk score. Returns the number of actors scored.
pub fn compute(conn: &mut PgConnection, risk: &RiskConfig, siem: &SiemConfig) -> anyhow::Result<usize> {
    let now = Utc::now();
    let window_floor = now - Duration::days(siem.window_days.max(1));
    let h24 = now - Duration::hours(24);
    let dormant_floor = now - Duration::days(siem.dormant_days.max(1));

    let factors: Vec<Factors> = diesel::sql_query(
        "WITH ev AS ( \
            SELECT aa.actor_id AS actor_id, e.ts AS ts, e.status AS status \
            FROM ssumgmt_events e \
            JOIN actor_aliases aa ON aa.alias = e.actor \
            WHERE e.ts >= $1 \
         ), \
         fa AS (SELECT actor_id, count(*) AS n FROM ev WHERE status = 'failure' AND ts >= $2 GROUP BY actor_id), \
         oh AS ( \
            SELECT actor_id, \
              count(*) FILTER (WHERE EXTRACT(hour FROM ts) >= $3 OR EXTRACT(hour FROM ts) < $4) AS off, \
              count(*) AS total \
            FROM ev GROUP BY actor_id \
         ), \
         recent AS ( \
            SELECT actor_id, max(ts) AS last_ts, max(ts) FILTER (WHERE ts < $2) AS prev_ts \
            FROM ev GROUP BY actor_id \
         ), \
         pg AS (SELECT actor_id, count(*) AS n FROM grants WHERE privileged AND revoked_at IS NULL AND actor_id IS NOT NULL GROUP BY actor_id), \
         fs AS (SELECT actor_id, count(*) AS n FROM sessions WHERE status = 'flagged' AND actor_id IS NOT NULL GROUP BY actor_id), \
         an AS (SELECT actor_id, count(*) AS n FROM anomalies WHERE event_time >= $1 AND actor_id IS NOT NULL GROUP BY actor_id) \
         SELECT a.id AS actor_id, \
           COALESCE(fa.n, 0) AS failed_auth, \
           COALESCE(pg.n, 0) AS priv_grants, \
           CASE WHEN COALESCE(oh.total, 0) > 0 THEN oh.off::float8 / oh.total ELSE 0 END AS off_hours_ratio, \
           (CASE WHEN recent.last_ts >= $2 AND (recent.prev_ts IS NULL OR recent.prev_ts < $5) AND a.first_seen < $5 THEN 1 ELSE 0 END)::bigint AS dormant, \
           COALESCE(fs.n, 0) AS flagged_sessions, \
           COALESCE(array_length(a.sources, 1), 0)::bigint AS source_diversity, \
           COALESCE(an.n, 0) AS anomalies \
         FROM actors a \
         LEFT JOIN fa     ON fa.actor_id = a.id \
         LEFT JOIN oh     ON oh.actor_id = a.id \
         LEFT JOIN recent ON recent.actor_id = a.id \
         LEFT JOIN pg     ON pg.actor_id = a.id \
         LEFT JOIN fs     ON fs.actor_id = a.id \
         LEFT JOIN an     ON an.actor_id = a.id",
    )
    .bind::<Timestamptz, _>(window_floor)
    .bind::<Timestamptz, _>(h24)
    .bind::<Double, _>(siem.off_hours_start as f64)
    .bind::<Double, _>(siem.off_hours_end as f64)
    .bind::<Timestamptz, _>(dormant_floor)
    .load(conn)
    .context("load risk factors")?;

    let mut scored = 0usize;
    conn.transaction::<_, anyhow::Error, _>(|conn| {
        for f in &factors {
            // Saturating per-factor transforms into [0, 1].
            let sat = |x: f64, cap: f64| (x / cap).clamp(0.0, 1.0);
            let f_failed = sat(f.failed_auth as f64, 10.0);
            let f_priv = sat(f.priv_grants as f64, 5.0);
            let f_off = f.off_hours_ratio.clamp(0.0, 1.0);
            let f_dormant = f.dormant.min(1) as f64;
            let f_flagged = sat(f.flagged_sessions as f64, 3.0);
            let f_diversity = sat((f.source_diversity - 1).max(0) as f64, 2.0);
            let f_anom = sat(f.anomalies as f64, 3.0);

            let contrib = [
                ("failed_auth", risk.w_failed_auth, f_failed, f.failed_auth as f64),
                ("priv_grants", risk.w_priv_grants, f_priv, f.priv_grants as f64),
                ("off_hours", risk.w_off_hours, f_off, f.off_hours_ratio),
                ("dormant_reactivation", risk.w_dormant, f_dormant, f.dormant as f64),
                ("flagged_sessions", risk.w_flagged_sessions, f_flagged, f.flagged_sessions as f64),
                ("source_diversity", risk.w_source_diversity, f_diversity, f.source_diversity as f64),
                ("anomalies", risk.w_anomalies, f_anom, f.anomalies as f64),
            ];

            let total: f64 = contrib.iter().map(|(_, w, fv, _)| w * fv).sum();
            let score = total.round().clamp(0.0, 100.0) as i32;
            let label = label_of(score);

            let mut components = serde_json::Map::new();
            for (name, w, fv, raw) in contrib.iter() {
                components.insert(
                    name.to_string(),
                    json!({ "raw": raw, "weight": w, "normalized": fv, "contribution": (w * fv * 100.0).round() / 100.0 }),
                );
            }
            let components = serde_json::Value::Object(components);

            diesel::sql_query(
                "INSERT INTO risk_scores (actor_id, score, label, components, computed_at) \
                 VALUES ($1, $2, $3, $4, now()) \
                 ON CONFLICT (actor_id) DO UPDATE SET \
                   score = EXCLUDED.score, label = EXCLUDED.label, components = EXCLUDED.components, computed_at = now()",
            )
            .bind::<Text, _>(&f.actor_id)
            .bind::<diesel::sql_types::Integer, _>(score)
            .bind::<Text, _>(label)
            .bind::<diesel::sql_types::Jsonb, _>(components)
            .execute(conn)
            .context("upsert risk score")?;
            scored += 1;
        }
        Ok(())
    })?;

    Ok(scored)
}
