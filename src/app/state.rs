use super::config::Config;
use crate::{app::jwt::TokenManager, auth::inbound::state::AuthState};
use std::sync::Arc;
use tower_cookies::Key;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub cookie_key: Key,
    pub token: Arc<dyn TokenManager>,
    // Each module gets its own state struct.
    pub auth: AuthState,
}
