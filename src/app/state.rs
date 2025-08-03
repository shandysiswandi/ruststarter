use super::config::Config;
use crate::{
    app::jwt::TokenManager,
    auth::usecase::{authn::AuthnUseCase, authz::AuthzUseCase, profile::ProfileUseCase},
};
use std::sync::Arc;
use tower_cookies::Key;

#[derive(Clone)]
pub struct AuthState {
    pub authn: Arc<dyn AuthnUseCase>,
    pub authz: Arc<dyn AuthzUseCase>,
    pub profile: Arc<dyn ProfileUseCase>,
}

impl AuthState {
    pub fn new(
        authn: Arc<dyn AuthnUseCase>,
        authz: Arc<dyn AuthzUseCase>,
        profile: Arc<dyn ProfileUseCase>,
    ) -> Self {
        Self {
            authn,
            authz,
            profile,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub cookie_key: Key,
    pub token: Arc<dyn TokenManager>,
    // Each module gets its own state struct.
    pub auth: AuthState,
}
