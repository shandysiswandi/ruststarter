use oauth2::{CsrfToken, PkceCodeVerifier};
use validator::Validate;

// ╔════════════════════════════╗
// ║         Login              ║
// ╚════════════════════════════╝

#[derive(Debug, Validate)]
pub struct LoginInput {
    #[validate(email(message = "must be a valid email address"))]
    pub email: String,
    #[validate(length(min = 8, message = "must be at least 8 characters long"))]
    pub password: String,
}

#[derive(Debug)]
pub enum LoginOutput {
    /// The final access and refresh tokens for a successful login.
    Success { access_token: String, refresh_token: String },
    /// Indicates that a second factor is required to complete the login.
    MfaRequired { mfa_required: bool, pre_auth_token: String },
}

// ╔════════════════════════════╗
// ║       Registration         ║
// ╚════════════════════════════╝

#[derive(Debug, Validate)]
pub struct RegisterInput {
    #[validate(length(min = 5, message = "must be at least 5 characters long"))]
    pub full_name: String,
    #[validate(email(message = "must be a valid email address"))]
    pub email: String,
    #[validate(length(min = 8, message = "must be at least 8 characters long"))]
    pub password: String,
}

#[derive(Debug)]
pub struct RegisterOutput {
    pub success: bool,
    pub message: String,
}

// ╔════════════════════════════╗
// ║       Verify Email         ║
// ╚════════════════════════════╝

#[derive(Debug, Validate)]
pub struct VerifyEmailInput {
    #[validate(length(min = 21))]
    pub token: String,
}

#[derive(Debug)]
pub struct VerifyEmailOutput {
    pub redirect: String,
}

// ╔════════════════════════════╗
// ║          Logout            ║
// ╚════════════════════════════╝

#[derive(Debug, Validate)]
pub struct LogoutInput {
    #[validate(length(min = 1, message = "refresh token cannot be empty"))]
    pub refresh_token: String,
}

#[derive(Debug)]
pub struct LogoutOutput {
    pub success: bool,
}

// ╔════════════════════════════╗
// ║       Refresh Token        ║
// ╚════════════════════════════╝

#[derive(Debug, Validate)]
pub struct RefreshTokenInput {
    #[validate(length(min = 1, message = "refresh token cannot be empty"))]
    pub refresh_token: String,
}

#[derive(Debug)]
pub struct RefreshTokenOutput {
    pub access_token: String,
    pub refresh_token: String,
}

// ╔════════════════════════════╗
// ║         Login 2FA          ║
// ╚════════════════════════════╝

#[derive(Debug, Validate)]
pub struct Login2faInput {
    #[validate(length(min = 1, message = "pre auth token cannot be empty"))]
    pub pre_auth_token: String,
    #[validate(length(equal = 6, message = "MFA code must be 6 digits"))]
    pub mfa_code: String,
}

#[derive(Debug)]
pub struct Login2faOutput {
    pub access_token: String,
    pub refresh_token: String,
}

// ╔════════════════════════════╗
// ║        Login OAuth         ║
// ╚════════════════════════════╝

#[derive(Debug, Validate)]
pub struct OAuthLoginInput {
    #[validate(length(min = 1, message = "provider cannot be empty"))]
    pub provider: String,
}

#[derive(Debug)]
pub struct OAuthLoginOutput {
    pub auth_url: String,
    pub csrf_token: CsrfToken,
    pub pkce_verifier: PkceCodeVerifier,
}

// ╔════════════════════════════╗
// ║   Login OAuth Callback     ║
// ╚════════════════════════════╝

#[derive(Debug, Validate)]
pub struct OAuthCallbackInput {
    #[validate(length(min = 1, message = "provider cannot be empty"))]
    pub provider: String,

    #[validate(length(min = 1, message = "code cannot be empty"))]
    pub code: String,

    pub pkce_verifier_secret: String,
}

#[derive(Debug)]
pub struct OAuthCallbackOutput {
    pub access_token: String,
    pub refresh_token: String,
}
