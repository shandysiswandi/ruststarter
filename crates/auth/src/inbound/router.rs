use std::sync::Arc;

use app_core::jwt::TokenManager;
use app_core::middleware::auth;
use axum::routing::{delete, get, post, put};
use axum::{Router, middleware};

use crate::inbound::http::authn::*;
use crate::inbound::http::authz::*;
use crate::inbound::http::profile::*;
use crate::inbound::state::AuthState;

pub fn create_router(state: AuthState, tm: Arc<dyn TokenManager>) -> Router {
    let protected_routes = Router::new()
        // profile scope
        .route("/me", get(get_profile).patch(update_profile))
        .route("/me/password", put(change_password))
        .route("/me/connections", get(list_connections))
        .route("/me/connections/{connection_id}", delete(delete_connection))
        .route("/me/mfa/factors", get(list_mfa_factors))
        .route("/me/mfa/factors/{factor_id}", delete(delete_mfa_factor))
        .route("/me/mfa/totp", post(setup_totp))
        .route("/me/mfa/totp/{factor_id}/verify", post(verify_totp))
        // authorization scope
        .route("/authz/users", get(list_users))
        .route("/authz/users/{user_id}", get(get_user).patch(update_user))
        .route("/users/{user_id}/roles", put(set_user_roles))
        // authentication scope
        .route("/auth/logout", post(logout))
        .route_layer(middleware::from_fn_with_state(tm, auth));

    let public_routes = Router::new()
        // authentication scope
        .route("/auth/login", post(login))
        .route("/auth/register", post(register))
        .route("/auth/verify-email", get(verify_email))
        .route("/auth/refresh-token", post(refresh_token))
        .route("/auth/login-2fa", post(login_2fa))
        .route("/auth/social/{provider}", get(oauth_login))
        .route("/auth/social/{provider}/callback", get(oauth_callback));

    Router::new().merge(public_routes).merge(protected_routes).with_state(state)
}
