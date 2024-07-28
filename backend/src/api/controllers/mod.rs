use axum::Router;
use crate::api::WebSharedState;

pub fn add_controllers(mut router : Router, state : WebSharedState) -> Router {
    // router = router.nest("/deployments", monitored_deployments::controller(state.clone()));
    // router = router.nest("/k8s", k8s::controller(state.clone()));

    router
}
