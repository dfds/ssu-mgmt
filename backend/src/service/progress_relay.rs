use std::time::Duration;

use log::{info, warn};
use postgres::fallible_iterator::FallibleIterator;
use postgres::Client;
use postgres_native_tls::MakeTlsConnector;
use tokio_util::sync::CancellationToken;

use crate::db::Config as DbConfig;
use crate::service::ingest::{publish_progress_local, PROGRESS_NOTIFY_CHANNEL};

pub fn spawn(conf: DbConfig, cancel: CancellationToken) {
    std::thread::spawn(move || relay_loop(conf, cancel));
}

fn relay_loop(conf: DbConfig, cancel: CancellationToken) {
    let conn_str = conf.connection_url();
    // Match libpq/Diesel's default `sslmode=prefer`: negotiate TLS when the server
    // offers it, fall back to plaintext otherwise. `accept_invalid_certs(true)` mirrors
    // `prefer`/`require`, which encrypt but do not verify the server certificate (so a
    // managed Postgres' non-system-root CA doesn't break the relay the way it doesn't
    // break libpq). The `postgres` crate's default ssl_mode is `Prefer`, so this connector
    // still works against the local plaintext dev DB.
    let connector = match native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => MakeTlsConnector::new(c),
        Err(e) => {
            warn!("progress relay: failed to build TLS connector: {e} — relay disabled");
            return;
        }
    };
    let mut backoff = 1u64;
    while !cancel.is_cancelled() {
        match Client::connect(&conn_str, connector.clone()) {
            Ok(mut client) => {
                backoff = 1; // connected — reset the backoff
                match listen(&mut client, &cancel) {
                    Ok(()) => break, // clean shutdown (cancel observed)
                    Err(e) => {
                        if cancel.is_cancelled() {
                            break;
                        }
                        warn!("progress relay error: {e} — reconnecting in {backoff}s");
                        sleep_interruptible(&cancel, backoff);
                        backoff = (backoff * 2).min(30);
                    }
                }
            }
            Err(e) => {
                if cancel.is_cancelled() {
                    break;
                }
                warn!("progress relay connect failed: {e} — retry in {backoff}s");
                sleep_interruptible(&cancel, backoff);
                backoff = (backoff * 2).min(30);
            }
        }
    }
    info!("progress relay stopped");
}

fn listen(client: &mut Client, cancel: &CancellationToken) -> Result<(), postgres::Error> {
    client.batch_execute(&format!("LISTEN {PROGRESS_NOTIFY_CHANNEL}"))?;
    info!("progress relay listening on {PROGRESS_NOTIFY_CHANNEL}");
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        let mut notifications = client.notifications();
        let mut iter = notifications.timeout_iter(Duration::from_secs(1));
        match iter.next()? {
            Some(n) => publish_progress_local(n.payload()),
            None => {}
        }
    }
}

/// Sleep up to `secs`, waking early if `cancel` fires (1s polling steps).
fn sleep_interruptible(cancel: &CancellationToken, secs: u64) {
    for _ in 0..secs {
        if cancel.is_cancelled() {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
