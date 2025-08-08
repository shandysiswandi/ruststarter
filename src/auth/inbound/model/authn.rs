use serde::{Deserialize, Serialize};

// ╔════════════════════════════╗
// ║    Login                   ║
// ╚════════════════════════════╝

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum LoginResponse {
    Success {
        access_token: String,
        refresh_token: String,
    },
    MfaRequired {
        mfa_required: bool,
        pre_auth_token: String,
    },
}

// ╔════════════════════════════╗
// ║    Register                ║
// ╚════════════════════════════╝

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub full_name: String,
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub message: String,
}

// ╔════════════════════════════╗
// ║    Logout                  ║
// ╚════════════════════════════╝

#[derive(Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct LogoutResponse {
    pub success: bool,
}

// ╔════════════════════════════╗
// ║    Refresh Token           ║
// ╚════════════════════════════╝

#[derive(Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

// ╔════════════════════════════╗
// ║    Login 2FA               ║
// ╚════════════════════════════╝

#[derive(Deserialize)]
pub struct Login2faRequest {
    pub pre_auth_token: String,
    pub mfa_code: String,
}

#[derive(Serialize)]
pub struct Login2faResponse {
    pub access_token: String,
    pub refresh_token: String,
}

// ╔════════════════════════════╗
// ║    OAuth Callback          ║
// ╚════════════════════════════╝

#[derive(Deserialize)]
pub struct OAuthCallbackRequest {
    pub error: Option<String>,
    pub code: Option<String>,
    pub state: String,
}

#[derive(Serialize)]
pub struct OAuthCallbackResponse {
    pub access_token: String,
    pub refresh_token: String,
}
