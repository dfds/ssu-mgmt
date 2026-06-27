pub mod cloudtrail;
pub mod github;
pub mod github_s3;

use std::sync::OnceLock;

use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel::sql_types::{BigInt, Nullable, Text, Timestamptz};
use diesel::PgConnection;
use tokio::sync::broadcast;

use crate::db::model::IngestWatermark;

static PROGRESS_HUB: OnceLock<broadcast::Sender<String>> = OnceLock::new();

pub fn init_progress_hub() -> broadcast::Sender<String> {
    let (tx, _rx) = broadcast::channel(256);
    let _ = PROGRESS_HUB.set(tx.clone());
    tx
}

pub fn progress_subscribe() -> Option<broadcast::Receiver<String>> {
    PROGRESS_HUB.get().map(|tx| tx.subscribe())
}

fn publish_progress(source: &str) {
    publish_progress_local(source);
}

pub fn publish_progress_local(source: &str) {
    if let Some(tx) = PROGRESS_HUB.get() {
        let _ = tx.send(source.to_owned());
    }
}

pub const PROGRESS_NOTIFY_CHANNEL: &str = "ssu_progress";

fn notify_progress(conn: &mut PgConnection, source: &str) {
    if let Err(e) = diesel::sql_query("SELECT pg_notify($1, $2)")
        .bind::<Text, _>(PROGRESS_NOTIFY_CHANNEL)
        .bind::<Text, _>(source)
        .execute(conn)
    {
        log::warn!("pg_notify progress fan-out failed for source {source}: {e}");
    }
}

pub const SOURCE_CLOUDTRAIL: &str = "cloudtrail";
pub const SOURCE_GITHUB: &str = "github";
pub const SOURCE_GITHUB_S3: &str = "github_s3";
pub const SOURCE_SIEM: &str = "siem";
pub const SOURCE_GUARDDUTY: &str = "guardduty";

/// Read the persisted watermark for a source, if any.
pub fn get_watermark(
    conn: &mut PgConnection,
    source: &str,
) -> QueryResult<Option<IngestWatermark>> {
    use crate::schema::ingest_watermarks::dsl as w;
    w::ingest_watermarks
        .filter(w::source.eq(source))
        .select(IngestWatermark::as_select())
        .first(conn)
        .optional()
}

pub fn advance_watermark(
    conn: &mut PgConnection,
    source: &str,
    last_object_key: Option<String>,
    last_event_at: Option<DateTime<Utc>>,
    last_cursor: Option<String>,
    objects_delta: i64,
    events_delta: i64,
) -> QueryResult<()> {
    diesel::sql_query(
        "INSERT INTO ingest_watermarks \
         (source, last_object_key, last_event_at, last_cursor, objects_scanned, events_applied, last_run_at, last_run_error) \
         VALUES ($1, $2, $3, $4, $5, $6, now(), NULL) \
         ON CONFLICT (source) DO UPDATE SET \
           last_object_key = GREATEST(EXCLUDED.last_object_key, ingest_watermarks.last_object_key), \
           last_event_at   = GREATEST(EXCLUDED.last_event_at, ingest_watermarks.last_event_at), \
           last_cursor     = COALESCE(EXCLUDED.last_cursor, ingest_watermarks.last_cursor), \
           objects_scanned = ingest_watermarks.objects_scanned + EXCLUDED.objects_scanned, \
           events_applied  = ingest_watermarks.events_applied + EXCLUDED.events_applied, \
           last_run_at     = now(), \
           last_run_error  = NULL",
    )
    .bind::<Text, _>(source.to_owned())
    .bind::<Nullable<Text>, _>(last_object_key)
    .bind::<Nullable<Timestamptz>, _>(last_event_at)
    .bind::<Nullable<Text>, _>(last_cursor)
    .bind::<BigInt, _>(objects_delta)
    .bind::<BigInt, _>(events_delta)
    .execute(conn)?;
    notify_progress(conn, source);
    publish_progress(source);
    Ok(())
}

pub fn record_run_error(conn: &mut PgConnection, source: &str, err: &str) -> QueryResult<()> {
    diesel::sql_query(
        "INSERT INTO ingest_watermarks (source, objects_scanned, events_applied, last_run_at, last_run_error) \
         VALUES ($1, 0, 0, now(), $2) \
         ON CONFLICT (source) DO UPDATE SET last_run_at = now(), last_run_error = $2",
    )
    .bind::<Text, _>(source)
    .bind::<Text, _>(err)
    .execute(conn)?;
    publish_progress(source);
    Ok(())
}
