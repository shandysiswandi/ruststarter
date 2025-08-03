use crate::auth::domain::authn::{
    Login2faOutput, LoginOutput, LogoutOutput, OAuthCallbackOutput, RefreshTokenOutput, RegisterOutput,
};
use serde::{Deserialize, Serialize};

// --- Login ---

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

impl From<LoginOutput> for LoginResponse {
    fn from(output: LoginOutput) -> Self {
        match output {
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
        }
    }
}

// --- Registration ---

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

impl From<RegisterOutput> for RegisterResponse {
    fn from(result: RegisterOutput) -> Self {
        Self {
            success: result.success,
            message: result.message,
        }
    }
}

// --- Logout ---

#[derive(Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct LogoutResponse {
    pub success: bool,
}

impl From<LogoutOutput> for LogoutResponse {
    fn from(result: LogoutOutput) -> Self {
        Self {
            success: result.success,
        }
    }
}

// --- Refresh Token ---

#[derive(Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

impl From<RefreshTokenOutput> for RefreshTokenResponse {
    fn from(result: RefreshTokenOutput) -> Self {
        Self {
            access_token: result.access_token,
            refresh_token: result.refresh_token,
        }
    }
}

// --- Login 2FA ---
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

impl From<Login2faOutput> for Login2faResponse {
    fn from(result: Login2faOutput) -> Self {
        Self {
            access_token: result.access_token,
            refresh_token: result.refresh_token,
        }
    }
}

// --- Oauth Callback ---

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

impl From<OAuthCallbackOutput> for OAuthCallbackResponse {
    fn from(result: OAuthCallbackOutput) -> Self {
        Self {
            access_token: result.access_token,
            refresh_token: result.refresh_token,
        }
    }
}
