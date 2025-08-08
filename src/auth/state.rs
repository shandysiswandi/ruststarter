use crate::auth::usecase::{authn::AuthnUseCase, authz::AuthzUseCase, profile::ProfileUseCase};
use std::sync::Arc;

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
