use crate::{
    app::error::AppError,
    auth::domain::entity::{mfa::MfaFactor, user_connection::UserConnection},
};
use axum::extract::Multipart;
use serde::{Deserialize, Serialize};

// -----

#[derive(Serialize)]
pub struct GetProfileResponse {
    pub id: i64,
    pub email: String,
    pub full_name: String,
    pub avatar_url: Option<String>,
}

// -----

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

// -----

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct ChangePasswordResponse {
    pub success: bool,
}

// -----

#[derive(Serialize)]
pub struct ConnectionResponse {
    pub id: i64,
    pub provider: String,
    pub provider_user_id: String,
}

impl From<UserConnection> for ConnectionResponse {
    fn from(output: UserConnection) -> Self {
        Self {
            id: output.id,
            provider: output.provider,
            provider_user_id: output.provider_user_id,
        }
    }
}

// -----

#[derive(Serialize)]
pub struct DeleteConnectionResponse {
    pub success: bool,
}

// -----

#[derive(Serialize)]
pub struct MfaFactorResponse {
    pub id: i64,
    pub mfa_type: String,
    pub friendly_name: Option<String>,
}

impl From<MfaFactor> for MfaFactorResponse {
    fn from(output: MfaFactor) -> Self {
        Self {
            id: output.id,
            mfa_type: output.mfa_type.to_string(),
            friendly_name: output.friendly_name,
        }
    }
}

// -----

#[derive(Serialize)]
pub struct DeleteMfaFactorResponse {
    pub success: bool,
}

// -----

#[derive(Deserialize)]
pub struct SetupTotpRequest {
    pub friendly_name: String,
}

#[derive(Serialize)]
pub struct SetupTotpResponse {
    pub factor_id: i64,
    pub secret: String,
    pub qr_code_image: String,
}

// -----

#[derive(Deserialize)]
pub struct VerifyTotpRequest {
    pub code: String,
}

#[derive(Serialize)]
pub struct VerifyTotpResponse {
    pub success: bool,
}
