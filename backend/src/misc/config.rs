use config::{ConfigBuilder};
use config::builder::DefaultState;
use serde::{Serialize, Deserialize};
use crate::messaging::config::MessagingConfig;
use crate::misc::error::SsuResult;

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Config {
    pub log_level : String,
    pub api_port : u16,
    pub api_listen_address : String,
    pub metrics_port : u16,
    pub metrics_listen_address : String,
    pub api_enable_auth : bool,
    pub enable_messaging_ingest : bool,
    pub auth : Auth,
    pub auth_jwks_url : Option<String>,
    pub cache_implementation : String,
    pub messaging : MessagingConfig,
    pub db : crate::db::Config
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct Auth {
    pub issuer : String,
    pub aud : String,
    pub oidc_url : String
}

pub fn get_conf_path() -> String {
    std::env::var("SSU__DATA_DIR").unwrap_or_else(|_| {"./".to_owned()})
}

pub fn load_conf() -> SsuResult<Config> {
    let mut settings = config::Config::builder()
        .add_source(config::Environment::with_prefix("SSU").separator("__"))
        .add_source(config::File::with_name(format!("{}/{}", get_conf_path(), "config.yaml").as_str()).required(false));
    settings = set_defaults(settings);
    let settings_built = settings
        .build()
        .unwrap();

    let config : Config = settings_built.try_deserialize()?;

    Ok(config)
}

fn set_defaults(builder : ConfigBuilder<DefaultState>) -> ConfigBuilder<DefaultState> {
    let builder = builder
        .set_default("auth.issuer", "").unwrap()
        .set_default("auth.aud", "").unwrap()
        .set_default("auth.oidc_url", "").unwrap()
        .set_default("api_port", 8080).unwrap()
        .set_default("api_listen_address", "0.0.0.0").unwrap()
        .set_default("metrics_port", 9000).unwrap()
        .set_default("metrics_listen_address", "0.0.0.0").unwrap()
        .set_default("log_level", "info").unwrap()
        .set_default("api_enable_auth", "true").unwrap()
        .set_default("enable_messaging_ingest", "true").unwrap()
        .set_default("cache_implementation", "inmemory").unwrap()
        .set_default("messaging.group_id", "ssu-mgmt").unwrap()
        .set_default("messaging.bootstrap_servers", "").unwrap()
        .set_default("messaging.sasl_mechanism", "GSSAPI").unwrap()
        .set_default("messaging.security_protocol", "PLAINTEXT").unwrap()
        .set_default("messaging.credentials.username", "").unwrap()
        .set_default("messaging.credentials.password", "").unwrap();
    builder
}
