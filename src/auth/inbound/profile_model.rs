use crate::{
    app::{error::AppError, jwt::Claims},
    auth::domain::{
        connection::Connection,
        mfa::MfaFactor,
        profile::{
            ChangePasswordInput, ChangePasswordOutput, DeleteConnectionOutput, DeleteMfaFactorOutput,
            GetProfileInput, GetProfileOutput, SetupTotpOutput, UpdateProfileInput, UpdateProfileOutput,
            VerifyTotpOutput,
        },
    },
};
use axum::extract::Multipart;
use serde::{Deserialize, Serialize};

// --- Get Profile ---

impl From<Claims> for GetProfileInput {
    fn from(claims: Claims) -> Self {
        Self { user_id: claims.sub }
    }
}

#[derive(Serialize)]
pub struct GetProfileResponse {
    pub id: i64,
    pub email: String,
    pub full_name: String,
}

impl From<GetProfileOutput> for GetProfileResponse {
    fn from(output: GetProfileOutput) -> Self {
        Self {
            id: output.id,
            email: output.email,
            full_name: output.full_name,
        }
    }
}

// --- Update Profile ---

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

impl From<(Claims, UpdateProfileRequest)> for UpdateProfileInput {
    fn from((claims, req): (Claims, UpdateProfileRequest)) -> Self {
        Self {
            user_id: claims.sub,
            full_name: req.full_name,
            avatar: req.avatar,
        }
    }
}

#[derive(Serialize)]
pub struct UpdateProfileResponse {
    pub success: bool,
}

impl From<UpdateProfileOutput> for UpdateProfileResponse {
    fn from(output: UpdateProfileOutput) -> Self {
        Self {
            success: output.success,
        }
    }
}

// --- Get User ---

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

impl From<(Claims, ChangePasswordRequest)> for ChangePasswordInput {
    fn from((claims, req): (Claims, ChangePasswordRequest)) -> Self {
        Self {
            user_id: claims.sub,
            old_password: req.old_password,
            new_password: req.new_password,
        }
    }
}

#[derive(Serialize)]
pub struct ChangePasswordResponse {
    pub success: bool,
}

impl From<ChangePasswordOutput> for ChangePasswordResponse {
    fn from(output: ChangePasswordOutput) -> Self {
        Self {
            success: output.success,
        }
    }
}

//

#[derive(Serialize)]
pub struct ConnectionResponse {
    pub id: i64,
    pub provider: String,
    pub provider_user_id: String,
}

impl From<Connection> for ConnectionResponse {
    fn from(output: Connection) -> Self {
        Self {
            id: output.id,
            provider: output.provider,
            provider_user_id: output.provider_user_id,
        }
    }
}

//

#[derive(Serialize)]
pub struct DeleteConnectionResponse {
    pub success: bool,
}

impl From<DeleteConnectionOutput> for DeleteConnectionResponse {
    fn from(output: DeleteConnectionOutput) -> Self {
        Self {
            success: output.success,
        }
    }
}

//

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
            friendly_name: Some(output.friendly_name),
        }
    }
}

//
#[derive(Serialize)]
pub struct DeleteMfaFactorResponse {
    pub success: bool,
}

impl From<DeleteMfaFactorOutput> for DeleteMfaFactorResponse {
    fn from(output: DeleteMfaFactorOutput) -> Self {
        Self {
            success: output.success,
        }
    }
}

//
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

impl From<SetupTotpOutput> for SetupTotpResponse {
    fn from(output: SetupTotpOutput) -> Self {
        Self {
            factor_id: output.factor_id,
            secret: output.secret,
            qr_code_image: output.qr_code_image,
        }
    }
}

//
#[derive(Deserialize)]
pub struct VerifyTotpRequest {
    pub code: String,
}

#[derive(Serialize)]
pub struct VerifyTotpResponse {
    pub success: bool,
}

impl From<VerifyTotpOutput> for VerifyTotpResponse {
    fn from(output: VerifyTotpOutput) -> Self {
        Self {
            success: output.success,
        }
    }
}
