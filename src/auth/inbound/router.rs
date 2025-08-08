use crate::app::middleware::auth;
use crate::app::state::AppState;
use crate::auth::inbound::http::authn::{
    login, login_2fa, logout, oauth_callback, oauth_login, refresh_token, register,
};
use crate::auth::inbound::http::authz::{get_user, list_users, set_user_roles, update_user};
use crate::auth::inbound::http::profile::{
    change_password, delete_connection, delete_mfa_factor, get_profile, list_connections, list_mfa_factors,
    setup_totp, update_profile, verify_totp,
};
use axum::routing::{delete, get, post, put};
use axum::{Router, middleware};

pub fn create_router(state: AppState) -> Router {
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
        .route_layer(middleware::from_fn_with_state(state.clone(), auth));

    let public_routes = Router::new()
        // authentication scope
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
