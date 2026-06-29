mod actors;
mod alerts;
pub mod auth_config;
mod entity;
mod graph;
mod meta;
mod overview;
pub mod progress;
mod query;
mod query_ast;

use crate::api::WebSharedState;
use axum::Router;

pub fn add_controllers(mut router: Router, state: WebSharedState) -> Router {
    let role_layer =
        || axum::middleware::from_fn_with_state("ce.cloudengineer", crate::api::auth::role_check);

    let query_routes = query::routes(state.db_pool.clone()).layer(role_layer());
    router = router.nest("/query", query_routes);

    let overview_routes = overview::routes(state.db_pool.clone()).layer(role_layer());
    router = router.nest("/overview", overview_routes);

    let entity_routes = entity::routes(state.db_pool.clone()).layer(role_layer());
    router = router.nest("/entity", entity_routes);

    let graph_routes = graph::routes(state.db_pool.clone()).layer(role_layer());
    router = router.nest("/graph", graph_routes);

    let alerts_routes = alerts::routes(state.db_pool.clone()).layer(role_layer());
    router = router.nest("/alerts", alerts_routes);

    let actors_routes = actors::routes(state.db_pool.clone()).layer(role_layer());
    router = router.nest("/actors", actors_routes);

    let meta_routes = meta::routes(state.db_pool.clone()).layer(role_layer());
    router = router.nest("/meta", meta_routes);

    router
}
