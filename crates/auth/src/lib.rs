mod domain;
mod inbound;
mod outbound;
mod usecase;

use std::sync::Arc;

use app_core::config::Config;
use app_core::crypto::Crypto;
use app_core::jwt::TokenManager;
use app_core::mail::Mailer;
use app_core::oauth::OAuthManager;
use app_core::password::Hasher;
use app_core::storage::StorageService;
use app_core::uid::Generator;
use bb8_redis::RedisConnectionManager;
use bb8_redis::bb8::Pool;
pub use inbound::router::create_router;
use sea_orm::DatabaseConnection;
use tower_cookies::Key;

use crate::inbound::state::AuthState;
use crate::outbound::orm::AuthORM;
use crate::outbound::session::SessionRedis;
use crate::usecase::authn::AuthnService;
use crate::usecase::authz::AuthzService;
use crate::usecase::profile::ProfileService;
pub struct Dependency {
    pub db: Arc<DatabaseConnection>,
    pub rds: Pool<RedisConnectionManager>,
    pub config: Arc<Config>,
    pub uid: Arc<dyn Generator>,
    pub hasher: Arc<dyn Hasher>,
    pub crypto: Arc<dyn Crypto>,
    pub token: Arc<dyn TokenManager>,
    pub mail: Arc<dyn Mailer>,
    pub storage: Arc<dyn StorageService>,
    pub oauth: OAuthManager,
    pub cookie_key: Key,
}

pub fn new(dep: Dependency) -> AuthState {
    let session = Arc::new(SessionRedis::new(dep.rds));
    let repo = Arc::new(AuthORM::new(dep.db, dep.uid.clone()));

    let authn_svc = Arc::new(AuthnService::new(
        dep.config.clone(),
        dep.hasher.clone(),
        dep.crypto.clone(),
        dep.uid.clone(),
        dep.token,
        dep.mail,
        dep.oauth,
        session,
        repo.clone(),
    ));
    let authz_svc = Arc::new(AuthzService::new(repo.clone()));
    let profile_svc = Arc::new(ProfileService::new(
        dep.config.clone(),
        dep.uid,
        dep.storage,
        dep.hasher,
        dep.crypto,
        repo,
    ));

    AuthState::new(dep.cookie_key, dep.config, authn_svc, authz_svc, profile_svc)
}
