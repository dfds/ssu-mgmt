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
    /// Pool sizing. Optional so existing `SSU__DB__*`-only deployments keep
    /// working; sane defaults are applied in `build_pool` when unset.
    pub pool_max_size: Option<u32>,
    pub pool_min_idle: Option<u32>,
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

/// Build the shared r2d2 connection pool. Panics on failure (boot-time only),
/// consistent with the existing connection-establish unwraps.
pub fn build_pool(conf: &Config) -> DbPool {
    let manager = ConnectionManager::<PgConnection>::new(conf.connection_url());
    Pool::builder()
        .max_size(conf.pool_max_size.unwrap_or(10))
        .min_idle(conf.pool_min_idle)
        .build(manager)
        .expect("failed to build database connection pool")
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
