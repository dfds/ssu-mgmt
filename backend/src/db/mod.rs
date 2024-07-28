pub mod model;

use serde::{Serialize, Deserialize};
use diesel::prelude::*;
use diesel::{ConnectionResult, PgConnection};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use log::{error, info};
use crate::misc::error::Error;


pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Config {
    pub host : String,
    pub port : u16,
    pub db_name : String,
    pub username : String,
    pub password : String
}

pub fn get_db_conn(conf : &Config) -> ConnectionResult<PgConnection> {
    PgConnection::establish(format!("postgres://{}:{}@{}:{}/{}", conf.username, conf.password, conf.host, conf.port, conf.db_name).as_str())
}

pub fn init(conf : &Config) -> Result<(), Error>{
    let mut conn = get_db_conn(conf).unwrap();

    let res = conn.run_pending_migrations(MIGRATIONS);

    if let Err(err) = res {
        error!("DB migrations failed :: {:?}", err);
        return Err(Error::DbError(err));
    }

    info!("Connected to database");
    Ok(())
}