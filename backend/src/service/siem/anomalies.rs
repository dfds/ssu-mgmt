use anyhow::Context;
use chrono::{DateTime, Duration, NaiveDate, Utc};
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Date, Double, Nullable, Text, Timestamptz};
use diesel::PgConnection;
use log::warn;

use crate::misc::config::SiemConfig;
use crate::service::ingest::get_watermark;

const FIRST_SEEN_WATERMARK_SOURCE: &str = "siem_first_seen";
const FIRST_SEEN_WATERMARK_LAG_MINS: i64 = 5;
const DAILY_COUNTS_WATERMARK_SOURCE: &str = "siem_daily_counts";
pub const DAILY_COUNTS_SAFETY_MARGIN_MINS: i64 = 15;
const IDENTITY_CONTEXT_WATERMARK_SOURCE: &str = "siem_identity_context";
pub const IDENTITY_CONTEXT_WATERMARK_LAG_MINS: i64 = 5;
const DETECTOR_STATEMENT_TIMEOUT: &str = "60s";
const MAX_HARVEST_STEP_HOURS: i64 = 3;

/// Run every anomaly detector. Returns the number of anomaly rows touched.
pub fn detect(conn: &mut PgConnection, siem: &SiemConfig) -> anyhow::Result<usize> {
    let now = Utc::now();
    let h24 = now - Duration::hours(24);
    let today_start = now
        .date_naive()
        .and_hms_opt(0, 0, 0)
        .map(|n| chrono::DateTime::<Utc>::from_naive_utc_and_offset(n, Utc))
        .unwrap_or(now);
    let window_floor_date = (now - Duration::days(siem.window_days.max(2))).date_naive();
    let ohs = siem.off_hours_start as f64;
    let ohe = siem.off_hours_end as f64;

    maintain_first_seen(conn).context("maintain first-seen cache")?;
    maintain_daily_counts(conn).context("maintain daily-counts cache")?;
    maintain_identity_context(conn).context("maintain identity-context cache")?;

    let mut touched = 0usize;
    touched += run_detector(conn, "volume_spike", |c| {
        volume_spike(c, siem, today_start, window_floor_date)
    });
    touched += run_detector(conn, "new_source", |c| new_source(c, h24));
    touched += run_detector(conn, "new_country", |c| new_country(c, h24));
    touched += run_detector(conn, "off_hours_spike", |c| {
        off_hours_spike(c, siem, today_start, window_floor_date, ohs, ohe)
    });

    Ok(touched)
}

/// Per-transaction guards shared by every maintenance/detector statement: a
/// `statement_timeout` shutdown-wedge backstop, plus `force_custom_plan` so the
/// planner estimates the `created_at`/`ts` range from the actual bind value.
/// Without it the cached prepared statement flips to a generic plan whose
/// default range estimate makes it scan the 7M-row `coalesce` index via a
/// pointless BitmapAnd — the harvest's ~4s timeout floor.
fn set_txn_guards(conn: &mut PgConnection) -> anyhow::Result<()> {
    diesel::sql_query(format!(
        "SET LOCAL statement_timeout = '{DETECTOR_STATEMENT_TIMEOUT}'"
    ))
    .execute(conn)
    .context("set statement_timeout")?;
    diesel::sql_query("SET LOCAL plan_cache_mode = 'force_custom_plan'")
        .execute(conn)
        .context("force custom plan")?;
    Ok(())
}

fn run_detector<F>(conn: &mut PgConnection, name: &str, f: F) -> usize
where
    F: FnOnce(&mut PgConnection) -> anyhow::Result<usize>,
{
    let result = conn.transaction::<usize, anyhow::Error, _>(|conn| {
        set_txn_guards(conn)?;
        f(conn)
    });
    match result {
        Ok(n) => n,
        Err(e) => {
            warn!("siem detector {name} failed, skipped this pass: {e:#}");
            0
        }
    }
}

fn volume_spike(
    conn: &mut PgConnection,
    siem: &SiemConfig,
    today_start: DateTime<Utc>,
    window_floor_date: NaiveDate,
) -> anyhow::Result<usize> {
    diesel::sql_query(
        "INSERT INTO anomalies (fingerprint, kind, actor_id, severity, score, baseline, observed, title, detail, evidence, event_time, updated_at) \
         WITH base AS ( \
           SELECT aa.actor_id AS actor_id, c.day, sum(c.n) AS n \
           FROM actor_daily_counts c JOIN actor_aliases aa ON aa.alias = c.actor \
           WHERE c.day >= $2 AND c.day < $3 \
           GROUP BY aa.actor_id, c.day \
         ), \
         stats AS ( \
           SELECT actor_id, avg(n)::float8 AS mean, coalesce(stddev_pop(n), 0)::float8 AS sd, count(*) AS hist_days \
           FROM base GROUP BY actor_id \
         ), \
         today AS ( \
           SELECT aa.actor_id AS actor_id, count(*)::float8 AS today_n, max(e.ts) AS last_ts \
           FROM ssumgmt_events e JOIN actor_aliases aa ON aa.alias = e.actor \
           WHERE e.ts >= $1 AND e.source <> 'ssu-mgmt' GROUP BY aa.actor_id \
         ), \
         scored AS ( \
           SELECT t.actor_id, t.today_n, t.last_ts, s.mean, s.sd, s.hist_days, \
             (t.today_n - s.mean) / NULLIF(s.sd, 0) AS z \
           FROM today t JOIN stats s ON s.actor_id = t.actor_id \
           WHERE s.hist_days >= $4 AND s.sd > 0 \
         ) \
         SELECT 'volume_spike:' || actor_id || ':' || to_char($1, 'YYYY-MM-DD'), \
           'volume_spike', actor_id, CASE WHEN z >= $5 + 2 THEN 'medium' ELSE 'low' END, \
           z, mean, today_n, 'Activity volume spike', \
           actor_id || ' produced ' || today_n::int || ' events today vs ~' || round(mean)::int || ' typical (z=' || round(z::numeric, 1) || ')', \
           jsonb_build_object('today', today_n, 'mean', mean, 'stddev', sd, 'z', z, 'hist_days', hist_days), \
           last_ts, now() \
         FROM scored WHERE z >= $5 \
         ON CONFLICT (fingerprint) DO UPDATE SET \
           score = EXCLUDED.score, baseline = EXCLUDED.baseline, observed = EXCLUDED.observed, \
           severity = EXCLUDED.severity, detail = EXCLUDED.detail, evidence = EXCLUDED.evidence, \
           event_time = EXCLUDED.event_time, updated_at = now()",
    )
    .bind::<Timestamptz, _>(today_start)
    .bind::<Date, _>(window_floor_date)
    .bind::<Date, _>(today_start.date_naive())
    .bind::<BigInt, _>(siem.anomaly_min_history_days.max(2))
    .bind::<Double, _>(siem.anomaly_z_threshold)
    .execute(conn)
    .context("detector volume_spike")
}


fn new_source(conn: &mut PgConnection, h24: DateTime<Utc>) -> anyhow::Result<usize> {
    diesel::sql_query(
        "INSERT INTO anomalies (fingerprint, kind, actor_id, severity, score, observed, title, detail, evidence, event_time, updated_at) \
         SELECT 'new_source:' || r.actor_id || ':' || r.source, 'new_source', r.actor_id, 'low', \
           1, NULL::float8, 'New source for actor', \
           r.actor_id || ' began appearing on source ' || r.source, \
           jsonb_build_object('source', r.source, 'first_seen', r.first_ts), r.last_ts, now() \
         FROM ( \
           SELECT aa.actor_id AS actor_id, f.source AS source, \
                  min(f.first_ts) AS first_ts, max(f.last_ts) AS last_ts \
           FROM actor_source_first_seen f JOIN actor_aliases aa ON aa.alias = f.actor \
           WHERE f.last_ts >= $1 \
           GROUP BY aa.actor_id, f.source \
         ) r \
         WHERE EXISTS (SELECT 1 FROM actor_aliases a JOIN actor_source_first_seen f ON f.actor = a.alias \
                       WHERE a.actor_id = r.actor_id AND f.first_ts < $1) \
           AND NOT EXISTS (SELECT 1 FROM actor_aliases a JOIN actor_source_first_seen f ON f.actor = a.alias \
                       WHERE a.actor_id = r.actor_id AND f.source = r.source AND f.first_ts < $1) \
         ON CONFLICT (fingerprint) DO UPDATE SET \
           observed = EXCLUDED.observed, detail = EXCLUDED.detail, evidence = EXCLUDED.evidence, \
           event_time = GREATEST(anomalies.event_time, EXCLUDED.event_time), updated_at = now()",
    )
    .bind::<Timestamptz, _>(h24)
    .execute(conn)
    .context("detector new_source")
}

fn new_country(conn: &mut PgConnection, h24: DateTime<Utc>) -> anyhow::Result<usize> {
    diesel::sql_query(
        "INSERT INTO anomalies (fingerprint, kind, actor_id, severity, score, observed, title, detail, evidence, event_time, updated_at) \
         SELECT 'new_country:' || s.actor_id || ':' || country, 'new_country', s.actor_id, 'medium', \
           1, count(*)::float8, 'Login from new country', \
           s.actor_id || ' logged in from ' || country || ' for the first time', \
           jsonb_build_object('country', country), max(s.last_seen_at), now() \
         FROM ( \
           SELECT actor_id, last_seen_at, \
             CASE WHEN position(', ' in location) > 0 \
                  THEN substring(location from position(', ' in location) + 2) \
                  ELSE location END AS country \
           FROM sessions WHERE actor_id IS NOT NULL AND location IS NOT NULL AND last_seen_at >= $1 \
         ) s \
         WHERE NOT EXISTS ( \
           SELECT 1 FROM sessions s2 WHERE s2.actor_id = s.actor_id AND s2.location IS NOT NULL AND s2.last_seen_at < $1 \
             AND (CASE WHEN position(', ' in s2.location) > 0 \
                       THEN substring(s2.location from position(', ' in s2.location) + 2) \
                       ELSE s2.location END) = s.country) \
         GROUP BY s.actor_id, country \
         ON CONFLICT (fingerprint) DO UPDATE SET \
           observed = EXCLUDED.observed, detail = EXCLUDED.detail, evidence = EXCLUDED.evidence, \
           event_time = GREATEST(anomalies.event_time, EXCLUDED.event_time), updated_at = now()",
    )
    .bind::<Timestamptz, _>(h24)
    .execute(conn)
    .context("detector new_country")
}

fn off_hours_spike(
    conn: &mut PgConnection,
    siem: &SiemConfig,
    today_start: DateTime<Utc>,
    window_floor_date: NaiveDate,
    ohs: f64,
    ohe: f64,
) -> anyhow::Result<usize> {
    diesel::sql_query(
        "INSERT INTO anomalies (fingerprint, kind, actor_id, severity, score, baseline, observed, title, detail, evidence, event_time, updated_at) \
         WITH base AS ( \
           SELECT aa.actor_id AS actor_id, c.day, \
             sum((SELECT coalesce(sum(v), 0) FROM unnest(c.hourly) WITH ORDINALITY AS u(v, ord) \
                  WHERE (ord - 1) >= $4 OR (ord - 1) < $5)) AS oh_n \
           FROM actor_daily_counts c JOIN actor_aliases aa ON aa.alias = c.actor \
           WHERE c.day >= $2 AND c.day < $3 \
           GROUP BY aa.actor_id, c.day \
         ), \
         stats AS (SELECT actor_id, coalesce(avg(oh_n), 0)::float8 AS mean FROM base GROUP BY actor_id), \
         today AS ( \
           SELECT aa.actor_id AS actor_id, \
             count(*) FILTER (WHERE EXTRACT(hour FROM e.ts) >= $4 OR EXTRACT(hour FROM e.ts) < $5)::float8 AS oh_n, \
             max(e.ts) FILTER (WHERE EXTRACT(hour FROM e.ts) >= $4 OR EXTRACT(hour FROM e.ts) < $5) AS last_ts \
           FROM ssumgmt_events e JOIN actor_aliases aa ON aa.alias = e.actor \
           WHERE e.ts >= $1 AND e.source <> 'ssu-mgmt' GROUP BY aa.actor_id \
         ) \
         SELECT 'off_hours_spike:' || t.actor_id || ':' || to_char($1, 'YYYY-MM-DD'), \
           'off_hours_spike', t.actor_id, 'low', t.oh_n - coalesce(s.mean, 0), coalesce(s.mean, 0), t.oh_n, \
           'Off-hours activity spike', \
           t.actor_id || ' had ' || t.oh_n::int || ' off-hours events today vs ~' || round(coalesce(s.mean, 0))::int || ' typical', \
           jsonb_build_object('today', t.oh_n, 'mean', coalesce(s.mean, 0)), t.last_ts, now() \
         FROM today t LEFT JOIN stats s ON s.actor_id = t.actor_id \
         WHERE t.oh_n >= $6 AND t.oh_n > coalesce(s.mean, 0) * 3 + 2 AND t.last_ts IS NOT NULL \
         ON CONFLICT (fingerprint) DO UPDATE SET \
           score = EXCLUDED.score, baseline = EXCLUDED.baseline, observed = EXCLUDED.observed, \
           detail = EXCLUDED.detail, evidence = EXCLUDED.evidence, event_time = EXCLUDED.event_time, updated_at = now()",
    )
    .bind::<Timestamptz, _>(today_start)
    .bind::<Date, _>(window_floor_date)
    .bind::<Date, _>(today_start.date_naive())
    .bind::<Double, _>(ohs)
    .bind::<Double, _>(ohe)
    .bind::<BigInt, _>(siem.off_hours_spike_min.max(1))
    .execute(conn)
    .context("detector off_hours_spike")
}

fn maintain_first_seen(conn: &mut PgConnection) -> anyhow::Result<()> {
    conn.transaction::<(), anyhow::Error, _>(|conn| {
        set_txn_guards(conn)?;

        #[derive(QueryableByName)]
        struct Snap {
            #[diesel(sql_type = Nullable<Timestamptz>)]
            w: Option<DateTime<Utc>>,
        }
        let target = diesel::sql_query(
            "SELECT GREATEST( \
               (SELECT max(created_at) FROM audit_records_selfservice) AT TIME ZONE 'UTC', \
               (SELECT max(created_at) FROM cloudtrail_events), \
               (SELECT max(created_at) FROM github_audit_events) \
             ) - ($1 || ' minutes')::interval AS w",
        )
        .bind::<Text, _>(FIRST_SEEN_WATERMARK_LAG_MINS.to_string())
        .get_result::<Snap>(conn)
        .context("snapshot first-seen watermark")?
        .w;
        let Some(target) = target else {
            return Ok(());
        };

        let w = get_watermark(conn, FIRST_SEEN_WATERMARK_SOURCE)
            .context("read first-seen watermark")?
            .and_then(|wm| wm.last_event_at)
            .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).expect("epoch"));

        // Bound the harvest to one step so a backlog drains in <60s increments.
        // The cache is idempotent (LEAST/GREATEST), so the exact boundary only
        // governs forward progress, not correctness.
        let boundary = target.min(w + Duration::hours(MAX_HARVEST_STEP_HOURS));

        diesel::sql_query(
            "INSERT INTO actor_source_first_seen (actor, source, first_ts, last_ts) \
             SELECT actor, source, min(ts) AS first_ts, max(ts) AS last_ts FROM ( \
               SELECT principal AS actor, 'selfservice'::text AS source, (timestamp AT TIME ZONE 'UTC') AS ts \
                 FROM audit_records_selfservice WHERE created_at > $1 AT TIME ZONE 'UTC' AND created_at <= $2 AT TIME ZONE 'UTC' \
               UNION ALL \
               SELECT COALESCE(principal_name, principal_arn), 'cloudtrail', event_time \
                 FROM cloudtrail_events WHERE created_at > $1 AND created_at <= $2 \
               UNION ALL \
               SELECT actor, 'github', event_time \
                 FROM github_audit_events WHERE created_at > $1 AND created_at <= $2 \
             ) x WHERE actor IS NOT NULL GROUP BY actor, source \
             ON CONFLICT (actor, source) DO UPDATE SET \
               first_ts = LEAST(actor_source_first_seen.first_ts, EXCLUDED.first_ts), \
               last_ts  = GREATEST(actor_source_first_seen.last_ts, EXCLUDED.last_ts), \
               updated_at = now()",
        )
        .bind::<Timestamptz, _>(w)
        .bind::<Timestamptz, _>(boundary)
        .execute(conn)
        .context("harvest first-seen cache")?;

        diesel::sql_query(
            "INSERT INTO ingest_watermarks \
               (source, last_event_at, last_run_at, objects_scanned, events_applied) \
             VALUES ($1, $2, now(), 0, 0) \
             ON CONFLICT (source) DO UPDATE SET \
               last_event_at = GREATEST(EXCLUDED.last_event_at, ingest_watermarks.last_event_at), \
               last_run_at   = now()",
        )
        .bind::<Text, _>(FIRST_SEEN_WATERMARK_SOURCE)
        .bind::<Timestamptz, _>(boundary)
        .execute(conn)
        .context("advance first-seen watermark")?;

        Ok(())
    })
}

fn maintain_daily_counts(conn: &mut PgConnection) -> anyhow::Result<()> {
    conn.transaction::<(), anyhow::Error, _>(|conn| {
        set_txn_guards(conn)?;

        let w = get_watermark(conn, DAILY_COUNTS_WATERMARK_SOURCE)
            .context("read daily-counts watermark")?
            .and_then(|wm| wm.last_event_at)
            .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).expect("epoch"));


        let target = Utc::now() - Duration::minutes(DAILY_COUNTS_SAFETY_MARGIN_MINS);
        let boundary = target.min(w + Duration::hours(MAX_HARVEST_STEP_HOURS));

        diesel::sql_query(
            "INSERT INTO actor_daily_counts (actor, day, n, hourly, failed) \
             WITH ev AS ( \
               SELECT principal AS actor, date_trunc('day', timestamp AT TIME ZONE 'UTC')::date AS day, \
                      extract(hour FROM (timestamp AT TIME ZONE 'UTC'))::int AS h, 0 AS fail \
                 FROM audit_records_selfservice \
                 WHERE created_at > $1 AT TIME ZONE 'UTC' AND created_at <= $2 AT TIME ZONE 'UTC' \
               UNION ALL \
               SELECT COALESCE(principal_name, principal_arn), date_trunc('day', event_time)::date, \
                      extract(hour FROM event_time)::int, \
                      (CASE WHEN error_code IS NOT NULL THEN 1 ELSE 0 END) \
                 FROM cloudtrail_events WHERE created_at > $1 AND created_at <= $2 \
               UNION ALL \
               SELECT actor, date_trunc('day', event_time)::date, extract(hour FROM event_time)::int, 0 \
                 FROM github_audit_events WHERE created_at > $1 AND created_at <= $2 \
             ), \
             per_hour AS (SELECT actor, day, h, count(*)::bigint AS cnt, sum(fail)::bigint AS fcnt \
                          FROM ev WHERE actor IS NOT NULL GROUP BY actor, day, h), \
             keys AS (SELECT DISTINCT actor, day FROM per_hour), \
             filled AS ( \
               SELECT k.actor, k.day, g.h, COALESCE(ph.cnt, 0) AS cnt, COALESCE(ph.fcnt, 0) AS fcnt \
                 FROM keys k CROSS JOIN generate_series(0, 23) g(h) \
                 LEFT JOIN per_hour ph ON ph.actor = k.actor AND ph.day = k.day AND ph.h = g.h \
             ) \
             SELECT actor, day, sum(cnt)::bigint, array_agg(cnt ORDER BY h), sum(fcnt)::bigint \
               FROM filled GROUP BY actor, day \
             ON CONFLICT (actor, day) DO UPDATE SET \
               n = actor_daily_counts.n + EXCLUDED.n, \
               hourly = (SELECT array_agg(COALESCE(o, 0) + COALESCE(e, 0) ORDER BY ord) \
                         FROM unnest(actor_daily_counts.hourly, EXCLUDED.hourly) WITH ORDINALITY AS t(o, e, ord)), \
               failed = actor_daily_counts.failed + EXCLUDED.failed, \
               updated_at = now()",
        )
        .bind::<Timestamptz, _>(w)
        .bind::<Timestamptz, _>(boundary)
        .execute(conn)
        .context("harvest daily-counts cache")?;

        diesel::sql_query(
            "INSERT INTO ingest_watermarks \
               (source, last_event_at, last_run_at, objects_scanned, events_applied) \
             VALUES ($1, $2, now(), 0, 0) \
             ON CONFLICT (source) DO UPDATE SET \
               last_event_at = GREATEST(EXCLUDED.last_event_at, ingest_watermarks.last_event_at), \
               last_run_at   = now()",
        )
        .bind::<Text, _>(DAILY_COUNTS_WATERMARK_SOURCE)
        .bind::<Timestamptz, _>(boundary)
        .execute(conn)
        .context("advance daily-counts watermark")?;

        Ok(())
    })
}

fn maintain_identity_context(conn: &mut PgConnection) -> anyhow::Result<()> {
    conn.transaction::<(), anyhow::Error, _>(|conn| {
        set_txn_guards(conn)?;

        #[derive(QueryableByName)]
        struct Snap {
            #[diesel(sql_type = Nullable<Timestamptz>)]
            w: Option<DateTime<Utc>>,
        }
        let target = diesel::sql_query(
            "SELECT (SELECT max(created_at) FROM cloudtrail_events) - ($1 || ' minutes')::interval AS w",
        )
        .bind::<Text, _>(IDENTITY_CONTEXT_WATERMARK_LAG_MINS.to_string())
        .get_result::<Snap>(conn)
        .context("snapshot identity-context watermark")?
        .w;
        let Some(target) = target else {
            return Ok(());
        };

        let w = get_watermark(conn, IDENTITY_CONTEXT_WATERMARK_SOURCE)
            .context("read identity-context watermark")?
            .and_then(|wm| wm.last_event_at)
            .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).expect("epoch"));

        // Bound the harvest to one step so a backlog drains in <60s increments.
        // The cache is idempotent (GREATEST), so the boundary only governs
        // forward progress, not correctness.
        let boundary = target.min(w + Duration::hours(MAX_HARVEST_STEP_HOURS));

        diesel::sql_query(
            "INSERT INTO actor_identity_context (actor, identity_source, assumed_role_arn, last_ts) \
             SELECT COALESCE(principal_name, principal_arn), \
                    COALESCE(identity_source, ''), COALESCE(assumed_role_arn, ''), max(event_time) \
               FROM cloudtrail_events \
              WHERE created_at > $1 AND created_at <= $2 \
                AND COALESCE(principal_name, principal_arn) IS NOT NULL \
                AND (identity_source IS NOT NULL OR assumed_role_arn IS NOT NULL) \
              GROUP BY 1, 2, 3 \
             ON CONFLICT (actor, identity_source, assumed_role_arn) DO UPDATE SET \
               last_ts = GREATEST(actor_identity_context.last_ts, EXCLUDED.last_ts), \
               updated_at = now()",
        )
        .bind::<Timestamptz, _>(w)
        .bind::<Timestamptz, _>(boundary)
        .execute(conn)
        .context("harvest identity-context cache")?;

        diesel::sql_query(
            "INSERT INTO ingest_watermarks \
               (source, last_event_at, last_run_at, objects_scanned, events_applied) \
             VALUES ($1, $2, now(), 0, 0) \
             ON CONFLICT (source) DO UPDATE SET \
               last_event_at = GREATEST(EXCLUDED.last_event_at, ingest_watermarks.last_event_at), \
               last_run_at   = now()",
        )
        .bind::<Text, _>(IDENTITY_CONTEXT_WATERMARK_SOURCE)
        .bind::<Timestamptz, _>(boundary)
        .execute(conn)
        .context("advance identity-context watermark")?;

        Ok(())
    })
}
