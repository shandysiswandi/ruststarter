use chrono::{DateTime, Utc};
use validator::Validate;

// ╔════════════════════════════╗
// ║        Get Profile         ║
// ╚════════════════════════════╝

#[derive(Debug, Validate)]
pub struct GetProfileInput {
    pub user_id: i64,
}

#[derive(Debug)]
pub struct GetProfileOutput {
    pub id: i64,
    pub email: String,
    pub full_name: String,
    pub avatar: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ╔════════════════════════════╗
// ║      Update Profile        ║
// ╚════════════════════════════╝

#[derive(Debug, Validate)]
pub struct UpdateProfileInput {
    pub user_id: i64,
    #[validate(length(min = 1, message = "full name cannot be empty"))]
    pub full_name: Option<String>,

    pub avatar: Option<(String, Vec<u8>)>,
}

#[derive(Debug)]
pub struct UpdateProfileOutput {
    pub success: bool,
}

// ╔════════════════════════════╗
// ║     Change Password        ║
// ╚════════════════════════════╝

#[derive(Debug, Validate)]
pub struct ChangePasswordInput {
    pub user_id: i64,

    #[validate(length(min = 8, message = "old password must be at least 8 characters long"))]
    pub old_password: String,

    #[validate(length(min = 8, message = "new password must be at least 8 characters long"))]
    pub new_password: String,
}

#[derive(Debug)]
pub struct ChangePasswordOutput {
    pub success: bool,
}

// ╔════════════════════════════╗
// ║     List Connections       ║
// ╚════════════════════════════╝

pub struct ListConnectionInput {
    pub user_id: i64,
}

// ╔════════════════════════════╗
// ║    Delete Connection       ║
// ╚════════════════════════════╝

pub struct DeleteConnectionInput {
    pub user_id: i64,
    pub connection_id: i64,
}

pub struct DeleteConnectionOutput {
    pub success: bool,
}

// ╔════════════════════════════╗
// ║    List MFA Factors        ║
// ╚════════════════════════════╝

pub struct ListMfaFactorInput {
    pub user_id: i64,
}

// ╔════════════════════════════╗
// ║   Delete MFA Factor        ║
// ╚════════════════════════════╝

pub struct DeleteMfaFactorInput {
    pub user_id: i64,
    pub mfa_factor_id: i64,
}

pub struct DeleteMfaFactorOutput {
    pub success: bool,
}

// ╔════════════════════════════╗
// ║      Setup TOTP            ║
// ╚════════════════════════════╝

#[derive(Validate)]
pub struct SetupTotpInput {
    pub user_id: i64,
    #[validate(length(min = 1))]
    pub friendly_name: String,
}

pub struct SetupTotpOutput {
    pub factor_id: i64,
    pub qr_code_image: String, // base64 encoded PNG
}

// ╔════════════════════════════╗
// ║      Verify TOTP           ║
// ╚════════════════════════════╝

#[derive(Validate)]
pub struct VerifyTotpInput {
    pub user_id: i64,
    pub factor_id: i64,
    #[validate(length(equal = 6))]
    pub code: String,
}

pub struct VerifyTotpOutput {
    pub success: bool,
}
