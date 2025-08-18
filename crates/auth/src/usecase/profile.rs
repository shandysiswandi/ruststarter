use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use app_core::config::Config;
use app_core::crypto::Crypto;
use app_core::error::AppError;
use app_core::password::Hasher;
use app_core::storage::StorageService;
use app_core::uid::Generator;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;
use validator::Validate;

use crate::domain::entity::mfa::{MfaFactor, MfaFactorType};
use crate::domain::entity::user::{User, UserUpdatePayload};
use crate::domain::entity::user_connection::UserConnection;
use crate::domain::inout::prelude::*;
use crate::outbound::repository::AuthRepository;

// Constants for better maintainability and security
const USER_NOT_FOUND_MSG: &str = "User not found";
const INVALID_OLD_PASSWORD_MSG: &str = "Invalid old password";
const INVALID_TOTP_CODE_MSG: &str = "Invalid TOTP code";
const MFA_FACTOR_UNVERIFIED_MSG: &str = "MFA factor not found or already verified";

// TOTP configuration constants
const TOTP_DIGITS: usize = 6;
const TOTP_SKEW: u8 = 1;
const TOTP_STEP: u64 = 30;
const TOTP_ALGORITHM: Algorithm = Algorithm::SHA1;

// File upload constants
const AVATAR_DIR: &str = "avatars";
const MAX_AVATAR_SIZE: usize = 5 * 1024 * 1024; // 5MB
const ALLOWED_AVATAR_TYPES: &[&str] = &["image/jpeg", "image/png", "image/jpg", "image/webp"];

#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait ProfileUseCase: Send + Sync {
    async fn get_profile(&self, input: GetProfileInput) -> Result<GetProfileOutput, AppError>;
    async fn update_profile(&self, input: UpdateProfileInput) -> Result<UpdateProfileOutput, AppError>;
    async fn change_password(&self, input: ChangePasswordInput) -> Result<ChangePasswordOutput, AppError>;
    async fn list_connections(&self, input: ListConnectionInput) -> Result<Vec<UserConnection>, AppError>;
    async fn delete_connection(&self, input: DeleteConnectionInput) -> Result<DeleteConnectionOutput, AppError>;
    async fn list_mfa_factors(&self, input: ListMfaFactorInput) -> Result<Vec<MfaFactor>, AppError>;
    async fn delete_mfa_factor(&self, input: DeleteMfaFactorInput) -> Result<DeleteMfaFactorOutput, AppError>;
    async fn setup_totp(&self, input: SetupTotpInput) -> Result<SetupTotpOutput, AppError>;
    async fn verify_totp(&self, input: VerifyTotpInput) -> Result<VerifyTotpOutput, AppError>;
}

#[derive(Clone)]
pub struct ProfileService {
    config: Arc<Config>,
    uid: Arc<dyn Generator>,
    storage: Arc<dyn StorageService>,
    hasher: Arc<dyn Hasher>,
    crypto: Arc<dyn Crypto>,
    repo: Arc<dyn AuthRepository>,
}

impl ProfileService {
    pub fn new(
        config: Arc<Config>,
        uid: Arc<dyn Generator>,
        storage: Arc<dyn StorageService>,
        hasher: Arc<dyn Hasher>,
        crypto: Arc<dyn Crypto>,
        repo: Arc<dyn AuthRepository>,
    ) -> Self {
        Self { config, uid, storage, hasher, crypto, repo }
    }

    async fn get_user_by_id(&self, user_id: i64) -> Result<User, AppError> {
        self.repo
            .find_user_by_id(user_id)
            .await?
            .ok_or_else(|| AppError::NotFound(USER_NOT_FOUND_MSG.to_string()))
    }

    fn validate_avatar_file(&self, file_name: &str, user_id: i64, data: &[u8]) -> Result<(String, String), AppError> {
        if data.len() > MAX_AVATAR_SIZE {
            return Err(AppError::ValidationStr("Avatar file too large (max 5MB)".to_string()));
        }

        let content_type = mime_guess::from_path(file_name).first_or_octet_stream().to_string();

        if !ALLOWED_AVATAR_TYPES.contains(&content_type.as_str()) {
            return Err(AppError::ValidationStr(
                "Invalid avatar format. Only JPEG, JPG, PNG, and WebP are allowed".to_string(),
            ));
        }

        let file_extension = std::path::Path::new(file_name)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("jpg");

        let secure_filename = format!("{}/{}{}.{}", AVATAR_DIR, user_id, Uuid::new_v4(), file_extension);

        Ok((secure_filename, content_type))
    }

    async fn upload_avatar(&self, user_id: i64, file_name: &str, data: Vec<u8>) -> Result<String, AppError> {
        let (secure_filename, content_type) = self.validate_avatar_file(file_name, user_id, &data)?;

        Ok(self.storage.upload_file(&secure_filename, data, &content_type).await?)
    }

    async fn validate_current_password(&self, user_id: i64, current_password: &str) -> Result<(), AppError> {
        let credential = self
            .repo
            .find_user_credential_by_user_id(user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User credentials not found".to_string()))?;

        if !self.hasher.verify(current_password, &credential.password)? {
            return Err(AppError::Unauthorized(INVALID_OLD_PASSWORD_MSG.to_string()));
        }

        Ok(())
    }

    fn create_totp_instance(&self, secret_bytes: Vec<u8>, account_name: String) -> Result<TOTP, AppError> {
        Ok(TOTP::new(
            TOTP_ALGORITHM,
            TOTP_DIGITS,
            TOTP_SKEW,
            TOTP_STEP,
            secret_bytes,
            Some(self.config.get::<String>("jwt.issuer")?),
            account_name,
        )?)
    }

    fn validate_totp_code(&self, totp: &TOTP, code: &str) -> Result<bool, AppError> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        Ok(totp.check(code, timestamp))
    }

    async fn safe_delete<F, Fut>(&self, user_id: i64, resource_id: i64, delete_fn: F) -> Result<(), AppError>
    where
        F: FnOnce(i64, i64) -> Fut,
        Fut: std::future::Future<Output = Result<(), AppError>>,
    {
        delete_fn(user_id, resource_id).await
    }
}

#[async_trait]
impl ProfileUseCase for ProfileService {
    async fn get_profile(&self, input: GetProfileInput) -> Result<GetProfileOutput, AppError> {
        let user = self.get_user_by_id(input.user_id).await?;

        Ok(GetProfileOutput {
            id: user.id,
            email: user.email,
            full_name: user.full_name,
            avatar: user.avatar_url,
            created_at: user.created_at,
            updated_at: user.updated_at,
        })
    }

    async fn update_profile(&self, input: UpdateProfileInput) -> Result<UpdateProfileOutput, AppError> {
        input.validate()?;

        let user = self.get_user_by_id(input.user_id).await?;

        let avatar_url = if let Some((file_name, data)) = input.avatar {
            Some(self.upload_avatar(input.user_id, &file_name, data).await?)
        } else {
            None
        };

        self.repo
            .update_user(UserUpdatePayload {
                id: user.id,
                email: None,
                full_name: input.full_name,
                avatar_url,
                status: None,
            })
            .await?;

        tracing::info!("Profile updated successfully for user: {}", input.user_id);

        Ok(UpdateProfileOutput { success: true })
    }

    async fn change_password(&self, input: ChangePasswordInput) -> Result<ChangePasswordOutput, AppError> {
        input.validate()?;

        let _user = self.get_user_by_id(input.user_id).await?;
        self.validate_current_password(input.user_id, &input.old_password).await?;

        if input.old_password == input.new_password {
            return Err(AppError::ValidationStr(
                "New password must be different from the current password".to_string(),
            ));
        }

        let new_hashed_password = self.hasher.hash(&input.new_password)?;

        self.repo.update_user_credential(input.user_id, &new_hashed_password).await?;

        tracing::info!("Password changed successfully for user: {}", input.user_id);

        // TODO: In production, consider invalidating all user sessions after password
        // change self.session_service.invalidate_all_user_sessions(input.
        // user_id).await?;

        Ok(ChangePasswordOutput { success: true })
    }

    async fn list_connections(&self, input: ListConnectionInput) -> Result<Vec<UserConnection>, AppError> {
        let user = self.get_user_by_id(input.user_id).await?;

        self.repo.find_user_connections_by_user_id(user.id).await
    }

    async fn delete_connection(&self, input: DeleteConnectionInput) -> Result<DeleteConnectionOutput, AppError> {
        self.safe_delete(input.user_id, input.connection_id, |user_id, conn_id| {
            self.repo.delete_oauth_user(user_id, conn_id)
        })
        .await?;

        tracing::info!("Connection {} deleted for user: {}", input.connection_id, input.user_id);

        Ok(DeleteConnectionOutput { success: true })
    }

    async fn list_mfa_factors(&self, input: ListMfaFactorInput) -> Result<Vec<MfaFactor>, AppError> {
        let user = self.get_user_by_id(input.user_id).await?;

        self.repo.find_mfa_factors_by_user_id(user.id).await
    }

    async fn delete_mfa_factor(&self, input: DeleteMfaFactorInput) -> Result<DeleteMfaFactorOutput, AppError> {
        self.safe_delete(input.user_id, input.mfa_factor_id, |user_id, factor_id| {
            self.repo.delete_mfa_factor_by_id(user_id, factor_id)
        })
        .await?;

        tracing::info!("MFA factor {} deleted for user: {}", input.mfa_factor_id, input.user_id);

        Ok(DeleteMfaFactorOutput { success: true })
    }

    async fn setup_totp(&self, input: SetupTotpInput) -> Result<SetupTotpOutput, AppError> {
        input.validate()?;

        let user = self.get_user_by_id(input.user_id).await?;
        let secret = Secret::default();
        let secret_bytes = secret.to_bytes()?;

        let secret_base64 = general_purpose::STANDARD.encode(&secret_bytes);
        let totp = self.create_totp_instance(secret_bytes, user.email.clone())?;

        let factor_id = self.uid.generate()?;
        self.repo
            .create_mfa_factor(MfaFactor {
                id: factor_id,
                user_id: user.id,
                mfa_type: MfaFactorType::Totp,
                friendly_name: Some(input.friendly_name),
                secret: self.crypto.encrypt(&secret_base64)?,
                is_verified: false,
            })
            .await?;

        Ok(SetupTotpOutput { factor_id, qr_code_image: totp.get_qr_base64().map_err(AppError::TotpQrGeneration)? })
    }

    async fn verify_totp(&self, input: VerifyTotpInput) -> Result<VerifyTotpOutput, AppError> {
        input.validate()?;

        let user = self.get_user_by_id(input.user_id).await?;
        let factor = self
            .repo
            .find_unverified_mfa_factor_by_id_and_user_id(input.user_id, input.factor_id)
            .await?
            .ok_or_else(|| AppError::NotFound(MFA_FACTOR_UNVERIFIED_MSG.to_string()))?;

        let decrypted_secret_base64 = self.crypto.decrypt(&factor.secret)?;
        let secret_bytes = general_purpose::STANDARD.decode(&decrypted_secret_base64).map_err(|er| {
            tracing::error!("error decoding base64 secret: {}", er);
            AppError::Internal
        })?;

        let totp = self.create_totp_instance(secret_bytes, user.email)?;

        if !self.validate_totp_code(&totp, &input.code)? {
            return Err(AppError::Unauthorized(INVALID_TOTP_CODE_MSG.to_string()));
        }

        self.repo.verify_mfa_factor(input.factor_id).await?;

        tracing::info!("TOTP factor {} verified for user: {}", input.factor_id, input.user_id);

        Ok(VerifyTotpOutput { success: true })
    }
}
