use crate::misc::config::load_conf;
use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct AuthConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub api_scope: String,
}

pub async fn handler() -> Json<AuthConfig> {
    let conf = load_conf().unwrap();
    Json(AuthConfig {
        tenant_id: conf.auth.tenant_id,
        client_id: conf.auth.client_id,
        api_scope: conf.auth.api_scope,
    })
}
