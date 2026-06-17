mod audit;
pub mod auth_config;

use axum::Router;
use crate::api::WebSharedState;

pub fn add_controllers(mut router : Router, _state : WebSharedState) -> Router {
    let audit_routes = audit::routes().layer(axum::middleware::from_fn_with_state(
        "ce.cloudengineer",
        crate::api::auth::role_check,
    ));
    router = router.nest("/audit", audit_routes);
    router
}
