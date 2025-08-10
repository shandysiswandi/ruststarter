use app_core::error::AppError;
use axum::extract::Multipart;
use serde::{Deserialize, Serialize};

use crate::domain::entity::mfa::MfaFactor;
use crate::domain::entity::user_connection::UserConnection;

// ╔════════════════════════════╗
// ║    Get Profile             ║
// ╚════════════════════════════╝

#[derive(Serialize)]
pub struct GetProfileResponse {
    pub id: i64,
    pub email: String,
    pub full_name: String,
    pub avatar_url: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ╔════════════════════════════╗
// ║    Update Profile          ║
// ╚════════════════════════════╝

pub struct UpdateProfileRequest {
    pub full_name: Option<String>,
    pub avatar: Option<(String, Vec<u8>)>, // (filename, file_bytes)
}

impl UpdateProfileRequest {
    pub async fn from_multipart(mut multipart: Multipart) -> Result<Self, AppError> {
        let mut full_name = None;
        let mut avatar = None;

        while let Some(field) = multipart.next_field().await? {
            let name = field.name().unwrap_or("").to_string();
            match name.as_str() {
                "full_name" => {
                    full_name = Some(field.text().await?);
                },
                "avatar" => {
                    let file_name = field.file_name().unwrap_or("avatar").to_string();
                    let data = field.bytes().await?.to_vec();
                    avatar = Some((file_name, data));
                },
                _ => (),
            }
        }

        Ok(Self { full_name, avatar })
    }
}

#[derive(Serialize)]
pub struct UpdateProfileResponse {
    pub success: bool,
}

// ╔════════════════════════════╗
// ║    Change Password         ║
// ╚════════════════════════════╝

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct ChangePasswordResponse {
    pub success: bool,
}

// ╔════════════════════════════╗
// ║    User Connection         ║
// ╚════════════════════════════╝

#[derive(Serialize)]
pub struct ConnectionResponse {
    pub id: i64,
    pub user_id: i64,
    pub provider: String,
    pub provider_user_id: String,
    pub created_at: String,
}

impl From<UserConnection> for ConnectionResponse {
    fn from(output: UserConnection) -> Self {
        Self {
            id: output.id,
            user_id: output.user_id,
            provider: output.provider,
            provider_user_id: output.provider_user_id,
            created_at: output.created_at.to_rfc3339(),
        }
    }
}

// ╔════════════════════════════╗
// ║    Delete User Connection  ║
// ╚════════════════════════════╝

#[derive(Serialize)]
pub struct DeleteConnectionResponse {
    pub success: bool,
}

// ╔════════════════════════════╗
// ║    MFA Factor              ║
// ╚════════════════════════════╝

#[derive(Serialize)]
pub struct MfaFactorResponse {
    pub id: i64,
    pub mfa_type: String,
    pub friendly_name: Option<String>,
}

impl From<MfaFactor> for MfaFactorResponse {
    fn from(output: MfaFactor) -> Self {
        Self { id: output.id, mfa_type: output.mfa_type.to_string(), friendly_name: output.friendly_name }
    }
}

// ╔════════════════════════════╗
// ║    Delete MFA Factor       ║
// ╚════════════════════════════╝

#[derive(Serialize)]
pub struct DeleteMfaFactorResponse {
    pub success: bool,
}

// ╔════════════════════════════╗
// ║    Setup TOTP              ║
// ╚════════════════════════════╝

#[derive(Deserialize)]
pub struct SetupTotpRequest {
    pub friendly_name: String,
}

#[derive(Serialize)]
pub struct SetupTotpResponse {
    pub factor_id: i64,
    pub qr_code_image: String,
}

// ╔════════════════════════════╗
// ║    Verify TOTP             ║
// ╚════════════════════════════╝

#[derive(Deserialize)]
pub struct VerifyTotpRequest {
    pub code: String,
}

#[derive(Serialize)]
pub struct VerifyTotpResponse {
    pub success: bool,
}
