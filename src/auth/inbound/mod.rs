mod authn_http;
mod authn_model;
mod authz_http;
mod authz_model;
mod profile_http;
mod profile_model;

use crate::app::middleware::auth;
use crate::app::state::AppState;
use crate::auth::inbound::authn_http::{
    login, login_2fa, logout, oauth_callback, oauth_login, refresh_token, register,
};
use crate::auth::inbound::authz_http::{get_user, list_users, update_user};
use crate::auth::inbound::profile_http::{
    change_password, delete_connection, delete_mfa_factor, get_profile, list_connections, list_mfa_factors,
    setup_totp, update_profile, verify_totp,
};
use axum::routing::{delete, get, post, put};
use axum::{Router, middleware};

pub fn create_router(state: AppState) -> Router {
    let protected_routes = Router::new()
        // me/profile scope
        .route("/me", get(get_profile).patch(update_profile))
        .route("/me/password", put(change_password))
        .route("/me/connections", get(list_connections))
        .route("/me/connections/{connectionId}", delete(delete_connection))
        .route("/me/mfa/factors", get(list_mfa_factors))
        .route("/me/mfa/factors/{factorId}", delete(delete_mfa_factor))
        .route("/me/mfa/totp", post(setup_totp))
        .route("/me/mfa/totp/{factorId}/verify", post(verify_totp))
        // authz scope
        .route("/authz/users", get(list_users))
        .route("/authz/users/{userId}", get(get_user).patch(update_user))
        // authn scope
        .route("/auth/logout", post(logout))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth));

    let public_routes = Router::new()
        .route("/auth/login", post(login))
        .route("/auth/register", post(register))
        .route("/auth/login/2fa", post(login_2fa))
        .route("/auth/refresh-token", post(refresh_token))
        .route("/auth/social/{provider}", get(oauth_login))
        .route("/auth/social/{provider}/callback", get(oauth_callback));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .with_state(state)
}
