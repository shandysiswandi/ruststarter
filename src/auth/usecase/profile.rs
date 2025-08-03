use crate::app::error::AppError;
use crate::app::password::Hasher;
use crate::app::storage::StorageService;
use crate::auth::domain::connection::Connection;
use crate::auth::domain::mfa::MfaFactor;
use crate::auth::domain::profile::{
    ChangePasswordInput, ChangePasswordOutput, DeleteConnectionInput, DeleteConnectionOutput,
    DeleteMfaFactorInput, DeleteMfaFactorOutput, GetProfileInput, GetProfileOutput, ListConnectionInput,
    ListMfaFactorInput, SetupTotpInput, SetupTotpOutput, UpdateProfileInput, UpdateProfileOutput,
    VerifyTotpInput, VerifyTotpOutput,
};
use crate::auth::outbound::sql::AuthDataSource;
use async_trait::async_trait;
use std::sync::Arc;
use totp_rs::{Algorithm, Secret, TOTP};
use validator::Validate;

#[async_trait]
pub trait ProfileUseCase: Send + Sync {
    async fn get_profile(&self, input: GetProfileInput) -> Result<GetProfileOutput, AppError>;
    async fn update_profile(&self, input: UpdateProfileInput) -> Result<UpdateProfileOutput, AppError>;
    async fn change_password(&self, input: ChangePasswordInput) -> Result<ChangePasswordOutput, AppError>;
    async fn list_connections(&self, input: ListConnectionInput) -> Result<Vec<Connection>, AppError>;
    async fn delete_connection(
        &self,
        input: DeleteConnectionInput,
    ) -> Result<DeleteConnectionOutput, AppError>;
    async fn list_mfa_factors(&self, input: ListMfaFactorInput) -> Result<Vec<MfaFactor>, AppError>;
    async fn delete_mfa_factor(&self, input: DeleteMfaFactorInput)
    -> Result<DeleteMfaFactorOutput, AppError>;
    async fn setup_totp(&self, input: SetupTotpInput) -> Result<SetupTotpOutput, AppError>;
    async fn verify_totp(&self, input: VerifyTotpInput) -> Result<VerifyTotpOutput, AppError>;
}

#[derive(Clone)]
pub struct ProfileService {
    storage: Arc<dyn StorageService>,
    hasher: Arc<dyn Hasher>,
    user_repo: Arc<dyn AuthDataSource>,
}

impl ProfileService {
    pub fn new(
        storage: Arc<dyn StorageService>,
        hasher: Arc<dyn Hasher>,
        user_repo: Arc<dyn AuthDataSource>,
    ) -> Self {
        Self {
            storage,
            hasher,
            user_repo,
        }
    }
}

#[async_trait]
impl ProfileUseCase for ProfileService {
    async fn get_profile(&self, input: GetProfileInput) -> Result<GetProfileOutput, AppError> {
        let user = self
            .user_repo
            .find_user_by_id(input.user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        Ok(GetProfileOutput {
            id: user.id,
            email: user.email,
            full_name: user.full_name,
        })
    }

    async fn update_profile(&self, input: UpdateProfileInput) -> Result<UpdateProfileOutput, AppError> {
        input.validate()?;

        let mut avatar_url = None;
        if let Some((file_name, data)) = input.avatar {
            let content_type = mime_guess::from_path(&file_name)
                .first_or_octet_stream()
                .to_string();
            let new_file_name = format!("avatars/{}-{}", input.user_id, file_name);

            let url = self
                .storage
                .upload_file(&new_file_name, data, &content_type)
                .await?;
            avatar_url = Some(url);
        }

        self.user_repo
            .update_user(input.user_id, input.full_name, avatar_url)
            .await?;

        Ok(UpdateProfileOutput { success: true })
    }

    async fn change_password(&self, input: ChangePasswordInput) -> Result<ChangePasswordOutput, AppError> {
        input.validate()?;

        let user = self
            .user_repo
            .find_user_by_id(input.user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        self.hasher
            .verify(&input.old_password, &user.password)?
            .then_some(())
            .ok_or_else(|| AppError::Unauthorized("Invalid old password".to_string()))?;

        let new_hashed_password = self.hasher.hash(&input.new_password)?;

        self.user_repo
            .update_password(input.user_id, &new_hashed_password)
            .await?;

        Ok(ChangePasswordOutput { success: true })
    }

    async fn list_connections(&self, input: ListConnectionInput) -> Result<Vec<Connection>, AppError> {
        let connections = self.user_repo.find_connections_by_user_id(input.user_id).await?;
        Ok(connections)
    }

    async fn delete_connection(
        &self,
        input: DeleteConnectionInput,
    ) -> Result<DeleteConnectionOutput, AppError> {
        let deleted_count = self
            .user_repo
            .delete_connection_by_id(input.user_id, input.connection_id)
            .await?;

        if deleted_count == 0 {
            return Err(AppError::NotFound(
                "Connection not found or you do not have permission to delete it".to_string(),
            ));
        }

        Ok(DeleteConnectionOutput { success: true })
    }

    async fn list_mfa_factors(&self, input: ListMfaFactorInput) -> Result<Vec<MfaFactor>, AppError> {
        let factors = self.user_repo.find_mfa_factors_by_user_id(input.user_id).await?;
        Ok(factors)
    }

    async fn delete_mfa_factor(
        &self,
        input: DeleteMfaFactorInput,
    ) -> Result<DeleteMfaFactorOutput, AppError> {
        let deleted_count = self
            .user_repo
            .delete_mfa_factor_by_id(input.user_id, input.mfa_factor_id)
            .await?;

        if deleted_count == 0 {
            return Err(AppError::NotFound(
                "MFA factor not found or you do not have permission to delete it".to_string(),
            ));
        }

        Ok(DeleteMfaFactorOutput { success: true })
    }

    async fn setup_totp(&self, input: SetupTotpInput) -> Result<SetupTotpOutput, AppError> {
        input.validate()?;

        let user = self
            .user_repo
            .find_user_by_id(input.user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        let secret = Secret::default();

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret.to_bytes()?,
            Some(input.issuer),
            user.email,
        )?;

        let factor_id = self
            .user_repo
            .create_mfa_factor(input.user_id, &secret.to_string(), &input.friendly_name)
            .await?;

        let qr_code_image = totp.get_qr_base64().map_err(|e| AppError::TotpQrGeneration(e))?;

        Ok(SetupTotpOutput {
            factor_id,
            secret: secret.to_string(),
            qr_code_image,
        })
    }

    async fn verify_totp(&self, input: VerifyTotpInput) -> Result<VerifyTotpOutput, AppError> {
        input.validate()?;

        let factor = self
            .user_repo
            .find_unverified_mfa_factor_by_id(input.user_id, input.factor_id)
            .await?
            .ok_or_else(|| AppError::NotFound("MFA factor not found or already verified".to_string()))?;

        let secret_bytes = Secret::Encoded(factor.secret).to_bytes()?;
        let totp = TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret_bytes, None, "".to_string());

        if !totp.check_current(&input.code).unwrap_or(false) {
            return Err(AppError::Unauthorized("Invalid TOTP code".to_string()));
        }

        // 3. If the code is valid, mark the factor as verified in the database.
        self.user_repo.verify_mfa_factor(input.factor_id).await?;

        Ok(VerifyTotpOutput { success: true })
    }
}
