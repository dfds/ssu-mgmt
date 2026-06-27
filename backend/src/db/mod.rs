pub mod model;
pub mod views;

use crate::misc::error::Error;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::{ConnectionResult, PgConnection};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use log::{error, info};
use serde::{Deserialize, Serialize};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

/// Shared connection pool. Synchronous r2d2 pool to match the existing
/// `spawn_blocking` + sync-Diesel pattern (no async-Diesel rewrite).
pub type DbPool = Pool<ConnectionManager<PgConnection>>;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub db_name: String,
    pub username: String,
    pub password: String,
    /// API pool sizing. Optional so existing `SSU__DB__*`-only deployments keep
    /// working; sane defaults are applied in `build_pool` when unset.
    pub pool_max_size: Option<u32>,
    pub pool_min_idle: Option<u32>,
    pub worker_pool_max_size: Option<u32>,
    pub worker_pool_min_idle: Option<u32>,
}

impl Config {
    pub fn connection_url(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.username, self.password, self.host, self.port, self.db_name
        )
    }
}

pub fn get_db_conn(conf: &Config) -> ConnectionResult<PgConnection> {
    PgConnection::establish(conf.connection_url().as_str())
}

/// Build the **API** r2d2 connection pool — serves HTTP request handlers only.
/// A short `connection_timeout` means that if this pool ever does saturate, a
/// handler fails fast with a retryable error instead of hanging for the r2d2
/// default of 30s (the old "frozen frontend"). Panics on failure (boot-time
/// only), consistent with the existing connection-establish unwraps.
pub fn build_pool(conf: &Config) -> DbPool {
    build_pool_inner(
        conf,
        conf.pool_max_size.unwrap_or(10),
        conf.pool_min_idle,
        std::time::Duration::from_secs(10),
    )
}

/// Build the **worker** r2d2 connection pool — serves the background ingest/SIEM
/// workers + the bg DB-writer. Kept entirely separate from the API pool so a
/// heavy CloudTrail sweep (which can hold connections for its whole multi-minute
/// run) contends only with other workers, never with API requests. Sized a bit
/// larger than the API pool and given the longer default acquire timeout, since
/// workers can afford to wait.
pub fn build_worker_pool(conf: &Config) -> DbPool {
    build_pool_inner(
        conf,
        conf.worker_pool_max_size.unwrap_or(16),
        conf.worker_pool_min_idle,
        std::time::Duration::from_secs(30),
    )
}

fn build_pool_inner(
    conf: &Config,
    max_size: u32,
    min_idle: Option<u32>,
    connection_timeout: std::time::Duration,
) -> DbPool {
    let manager = ConnectionManager::<PgConnection>::new(conf.connection_url());
    Pool::builder()
        .max_size(max_size)
        .min_idle(min_idle)
        .connection_timeout(connection_timeout)
        .build(manager)
        .expect("failed to build database connection pool")
}

/// Get a pooled connection, mapping a saturated-pool acquire timeout into a
/// diesel error instead of panicking. A `pool.get().unwrap()` in a request
/// handler's `spawn_blocking` panicked the blocking thread on a saturated pool —
/// noisy in the log and, worse, every overview endpoint did it at once during a
/// pool-starving CloudTrail sweep. Callers flow this through their existing
/// `QueryResult` error arm, so a saturated pool degrades to a clean 500 with a
/// message rather than a thread panic. (Mirrors the wrap already used in
/// `service::timeline::refresh`.)
pub fn conn(
    pool: &DbPool,
) -> diesel::QueryResult<diesel::r2d2::PooledConnection<ConnectionManager<PgConnection>>> {
    pool.get().map_err(|e| {
        diesel::result::Error::QueryBuilderError(Box::new(std::io::Error::other(format!(
            "db pool exhausted: {e}"
        ))))
    })
}

pub fn init(conf: &Config) -> Result<(), Error> {
    let mut conn = get_db_conn(conf).unwrap();

    let res = conn.run_pending_migrations(MIGRATIONS);

    if let Err(err) = res {
        error!("DB migrations failed :: {:?}", err);
        return Err(Error::DbError(err));
    }

    info!("Connected to database");
    Ok(())
}
