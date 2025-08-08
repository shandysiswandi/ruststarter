use crate::app::error::AppError;
use crate::app::extractors::{AppJson, AppPath, AppQuery};
use crate::app::response::Response;
use crate::app::state::AppState;
use crate::auth::domain::inout::prelude::*;
use crate::auth::inbound::model::prelude::*;
use axum::{
    debug_handler,
    extract::State,
    response::{IntoResponse, Redirect},
};
use serde_json::json;
use tower_cookies::{Cookie, Cookies, cookie::time};

const COOKIE_OAUTH_STATE: &str = "__oauth_state";
const KEY_OAUTH_STATE_CSRF: &str = "csrf_token";
const KEY_OAUTH_STATE_PKCE: &str = "pkce_verifier";

#[debug_handler]
pub async fn login(State(state): State<AppState>, AppJson(req): AppJson<LoginRequest>) -> impl IntoResponse {
    state
        .auth
        .authn
        .login(LoginInput {
            email: req.email,
            password: req.password,
        })
        .await
        .map(|output| match output {
            LoginOutput::Success {
                access_token,
                refresh_token,
            } => LoginResponse::Success {
                access_token,
                refresh_token,
            },
            LoginOutput::MfaRequired {
                mfa_required,
                pre_auth_token,
            } => LoginResponse::MfaRequired {
                mfa_required,
                pre_auth_token,
            },
        })
        .map(Response::from)
}

#[debug_handler]
pub async fn register(
    State(state): State<AppState>,
    AppJson(req): AppJson<RegisterRequest>,
) -> impl IntoResponse {
    state
        .auth
        .authn
        .register(RegisterInput {
            full_name: req.full_name,
            email: req.email,
            password: req.password,
        })
        .await
        .map(|output| RegisterResponse {
            success: output.success,
            message: output.message,
        })
        .map(Response::from)
}

#[debug_handler]
pub async fn refresh_token(
    State(state): State<AppState>,
    AppJson(req): AppJson<RefreshTokenRequest>,
) -> impl IntoResponse {
    state
        .auth
        .authn
        .refresh_token(RefreshTokenInput {
            refresh_token: req.refresh_token,
        })
        .await
        .map(|output| RefreshTokenResponse {
            access_token: output.access_token,
            refresh_token: output.refresh_token,
        })
        .map(Response::from)
}

#[debug_handler]
pub async fn logout(
    State(state): State<AppState>,
    AppJson(req): AppJson<LogoutRequest>,
) -> impl IntoResponse {
    state
        .auth
        .authn
        .logout(LogoutInput {
            refresh_token: req.refresh_token,
        })
        .await
        .map(|output| LogoutResponse {
            success: output.success,
        })
        .map(Response::from)
}

#[debug_handler]
pub async fn login_2fa(
    State(state): State<AppState>,
    AppJson(req): AppJson<Login2faRequest>,
) -> impl IntoResponse {
    state
        .auth
        .authn
        .login_2fa(Login2faInput {
            pre_auth_token: req.pre_auth_token,
            mfa_code: req.mfa_code,
        })
        .await
        .map(|output| Login2faResponse {
            access_token: output.access_token,
            refresh_token: output.refresh_token,
        })
        .map(Response::from)
}

#[debug_handler]
pub async fn oauth_login(
    State(state): State<AppState>,
    cookies: Cookies,
    AppPath(provider): AppPath<String>,
) -> impl IntoResponse {
    state
        .auth
        .authn
        .oauth_login(OAuthLoginInput { provider })
        .await
        .and_then(|output| {
            let oauth_state = json!({
                KEY_OAUTH_STATE_CSRF: output.csrf_token,
                KEY_OAUTH_STATE_PKCE: output.pkce_verifier,
            });

            let cookie = Cookie::build((COOKIE_OAUTH_STATE, serde_json::to_string(&oauth_state)?))
                .http_only(true)
                .secure(true)
                .path("/")
                .max_age(time::Duration::minutes(3))
                .build();

            cookies.private(&state.cookie_key).add(cookie);

            Ok(Redirect::to(&output.auth_url))
        })
}

#[debug_handler]
pub async fn oauth_callback(
    State(state): State<AppState>,
    cookies: Cookies,
    AppPath(provider): AppPath<String>,
    AppQuery(query): AppQuery<OAuthCallbackRequest>,
) -> impl IntoResponse {
    if let Some(err) = query.error {
        return Err(AppError::Forbidden(format!("OAuth authentication failed: {err}")));
    }

    let code = query
        .code
        .ok_or_else(|| AppError::Forbidden("Missing authorization code".to_string()))?;

    let oauth_state_cookie = cookies
        .private(&state.cookie_key)
        .get(COOKIE_OAUTH_STATE)
        .ok_or_else(|| AppError::Forbidden("OAuth session expired or invalid".to_string()))?;

    cookies
        .private(&state.cookie_key)
        .remove(Cookie::new(COOKIE_OAUTH_STATE, ""));

    let oauth_state: serde_json::Value = serde_json::from_str(oauth_state_cookie.value())
        .map_err(|_| AppError::Forbidden("Invalid OAuth state format".to_string()))?;

    let stored_csrf_token = oauth_state
        .get(KEY_OAUTH_STATE_CSRF)
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Forbidden("Invalid OAuth state structure".to_string()))?;

    if query.state != stored_csrf_token {
        return Err(AppError::Forbidden("Invalid OAuth state token".to_string()));
    }

    let pkce_verifier_secret = oauth_state[KEY_OAUTH_STATE_PKCE]
        .as_str()
        .ok_or_else(|| AppError::Internal)?
        .to_string();

    tracing::info!("nyampe gak {:?}", pkce_verifier_secret);

    state
        .auth
        .authn
        .oauth_callback(OAuthCallbackInput {
            provider,
            code,
            pkce_verifier_secret,
        })
        .await
        .map(|output| OAuthCallbackResponse {
            access_token: output.access_token,
            refresh_token: output.refresh_token,
        })
        .map(Response::from)
}
