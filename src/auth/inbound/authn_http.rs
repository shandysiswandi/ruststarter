use super::authn_model::{
    Login2faRequest, Login2faResponse, LoginRequest, LoginResponse, LogoutRequest, LogoutResponse,
    OAuthCallbackRequest, OAuthCallbackResponse, RefreshTokenRequest, RefreshTokenResponse, RegisterRequest,
    RegisterResponse,
};
use crate::app::error::AppError;
use crate::app::extractors::{AppJson, AppPath, AppQuery};
use crate::app::response::Response;
use crate::app::state::AppState;
use crate::auth::domain::authn::{
    Login2faInput, LoginInput, LogoutInput, OAuthCallbackInput, OAuthLoginInput, RefreshTokenInput,
    RegisterInput,
};
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
        .map(LoginResponse::from)
        .map(Response::new)
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
        .map(RegisterResponse::from)
        .map(Response::new)
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
        .map(RefreshTokenResponse::from)
        .map(Response::new)
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
        .map(LogoutResponse::from)
        .map(Response::new)
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
        .map(Login2faResponse::from)
        .map(Response::new)
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
        return Err(AppError::Forbidden(format!("Error OAuth from provider {}", err)));
    }

    let oauth_state_cookie = cookies
        .private(&state.cookie_key)
        .get(COOKIE_OAUTH_STATE)
        .ok_or_else(|| AppError::Forbidden("Missing or invalid OAuth cookie".to_string()))?;

    cookies
        .private(&state.cookie_key)
        .remove(Cookie::new(COOKIE_OAUTH_STATE, ""));

    let oauth_state: serde_json::Value = serde_json::from_str(oauth_state_cookie.value())?;

    let stored_csrf_str = oauth_state[KEY_OAUTH_STATE_CSRF]
        .as_str()
        .ok_or_else(|| AppError::Internal)?;

    if query.state != stored_csrf_str {
        return Err(AppError::Forbidden("Invalid OAuth state".to_string()));
    }

    let pkce_verifier_secret = oauth_state[KEY_OAUTH_STATE_PKCE]
        .as_str()
        .ok_or_else(|| AppError::Internal)?
        .to_string();

    tracing::info!("nyampe gak {:?}", pkce_verifier_secret);

    if let None = query.code {
        return Err(AppError::Forbidden("Invalid OAuth code".to_string()));
    }

    state
        .auth
        .authn
        .oauth_callback(OAuthCallbackInput {
            provider,
            code: query.code.unwrap(),
            pkce_verifier_secret,
        })
        .await
        .map(OAuthCallbackResponse::from)
        .map(Response::new)
}
