use std::sync::Arc;

use app_core::config::Config;
use tower_cookies::Key;

use crate::usecase::authn::AuthnUseCase;
use crate::usecase::authz::AuthzUseCase;
use crate::usecase::profile::ProfileUseCase;

#[derive(Clone)]
pub struct AuthState {
    pub cookie_key: Key,
    pub config: Arc<Config>,
    pub authn: Arc<dyn AuthnUseCase>,
    pub authz: Arc<dyn AuthzUseCase>,
    pub profile: Arc<dyn ProfileUseCase>,
}

impl AuthState {
    pub fn new(
        cookie_key: Key,
        config: Arc<Config>,
        authn: Arc<dyn AuthnUseCase>,
        authz: Arc<dyn AuthzUseCase>,
        profile: Arc<dyn ProfileUseCase>,
    ) -> Self {
        Self { cookie_key, config, authn, authz, profile }
    }
}

#[cfg(test)]
mod tests {
    use app_core::config::test_utils::TestConfigBuilder;

    use super::*;
    use crate::usecase::authn::MockAuthnUseCase;
    use crate::usecase::authz::MockAuthzUseCase;
    use crate::usecase::profile::MockProfileUseCase;

    #[test]
    fn test_auth_state_new() {
        let cookie_key = Key::generate();
        let authn: Arc<dyn AuthnUseCase> = Arc::new(MockAuthnUseCase::new());
        let authz: Arc<dyn AuthzUseCase> = Arc::new(MockAuthzUseCase::new());
        let profile: Arc<dyn ProfileUseCase> = Arc::new(MockProfileUseCase::new());

        let config = Arc::new(TestConfigBuilder::new().build());

        let state = AuthState::new(cookie_key.clone(), config, authn.clone(), authz.clone(), profile.clone());

        assert!(Arc::ptr_eq(&state.authn, &authn));
        assert!(Arc::ptr_eq(&state.authz, &authz));
        assert!(Arc::ptr_eq(&state.profile, &profile));
        assert_eq!(state.cookie_key.master(), cookie_key.master());
    }
}
