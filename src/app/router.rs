use super::state::AppState;
use crate::auth;
use axum::{Json, Router, http::StatusCode, routing};

pub fn create_router_app(app_state: AppState) -> Router {
    Router::new()
        .merge(auth::inbound::create_router(app_state.clone()))
        .route(
            "/",
            routing::get(|| async { Json(serde_json::json!({"message": "Hello from Rust Starter"})) }),
        )
        .fallback(|| async {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"message": "Endpoint not found"})),
            )
        })
        .method_not_allowed_fallback(|| async {
            (
                StatusCode::METHOD_NOT_ALLOWED,
                Json(serde_json::json!({"message": "Method not allowed"})),
            )
        })
}
