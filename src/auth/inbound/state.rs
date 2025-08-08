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

#[cfg(test)]
mod tests {
    use crate::auth::usecase::authn::MockAuthnUseCase;
    use crate::auth::usecase::authz::MockAuthzUseCase;
    use crate::auth::usecase::profile::MockProfileUseCase;

    use super::*;

    #[test]
    fn test_auth_state_new() {
        let authn: Arc<dyn AuthnUseCase> = Arc::new(MockAuthnUseCase::new());
        let authz: Arc<dyn AuthzUseCase> = Arc::new(MockAuthzUseCase::new());
        let profile: Arc<dyn ProfileUseCase> = Arc::new(MockProfileUseCase::new());

        let state = AuthState::new(authn.clone(), authz.clone(), profile.clone());

        assert!(Arc::ptr_eq(&state.authn, &authn));
        assert!(Arc::ptr_eq(&state.authz, &authz));
        assert!(Arc::ptr_eq(&state.profile, &profile));
    }
}
