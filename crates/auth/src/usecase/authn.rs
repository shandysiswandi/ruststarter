use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use app_core::config::Config;
use app_core::crypto::Crypto;
use app_core::error::AppError;
use app_core::jwt::TokenManager;
use app_core::mail::{Email, Mailer};
use app_core::oauth::{OAuthManager, OAuthUserProfile as OAuthUserData};
use app_core::password::Hasher;
use app_core::uid::Generator;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose;
use chrono::{Duration, Utc};
use totp_rs::{Algorithm, TOTP};
use uuid::Uuid;
use validator::Validate;

use crate::domain::entity::mfa::{MfaFactor, MfaFactorType};
use crate::domain::entity::oauth::OAuthUserProfile;
use crate::domain::entity::user::{NewUser, User, UserStatus};
use crate::domain::inout::prelude::*;
use crate::outbound::repository::AuthRepository;
use crate::outbound::session::SessionRepository;

// Constants for better maintainability
const INVALID_CREDENTIALS_MSG: &str = "Invalid email or password";
const INACTIVE_ACCOUNT_MSG: &str = "Your account is not active. Please verify your email or contact support.";
const INVALID_MFA_CODE_MSG: &str = "Invalid MFA code";
const INVALID_REFRESH_TOKEN_MSG: &str = "Invalid refresh token";
const MFA_NOT_ENABLED_MSG: &str = "MFA is not enabled for this user";
const EMAIL_EXISTS_MSG: &str = "A user with this email already exists";
const VERIFICATION_MSG: &str = "Please verify your email to activate your account.";

// TOTP configuration constants
const TOTP_DIGITS: usize = 6;
const TOTP_SKEW: u8 = 1;
const TOTP_STEP: u64 = 30;

#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait AuthnUseCase: Send + Sync {
    async fn login(&self, input: LoginInput) -> Result<LoginOutput, AppError>;
    async fn register(&self, input: RegisterInput) -> Result<RegisterOutput, AppError>;
    async fn verify_email(&self, input: VerifyEmailInput) -> Result<VerifyEmailOutput, AppError>;
    async fn logout(&self, input: LogoutInput) -> Result<LogoutOutput, AppError>;
    async fn refresh_token(&self, input: RefreshTokenInput) -> Result<RefreshTokenOutput, AppError>;
    async fn login_2fa(&self, input: Login2faInput) -> Result<Login2faOutput, AppError>;
    async fn oauth_login(&self, input: OAuthLoginInput) -> Result<OAuthLoginOutput, AppError>;
    async fn oauth_callback(&self, input: OAuthCallbackInput) -> Result<OAuthCallbackOutput, AppError>;
}

#[derive(Clone)]
pub struct AuthnService {
    config: Arc<Config>,
    hasher: Arc<dyn Hasher>,
    crypto: Arc<dyn Crypto>,
    uid: Arc<dyn Generator>,
    token: Arc<dyn TokenManager>,
    mail: Arc<dyn Mailer>,
    oauth: OAuthManager,
    session: Arc<dyn SessionRepository>,
    repo: Arc<dyn AuthRepository>,
}

impl AuthnService {
    pub fn new(
        config: Arc<Config>,
        hasher: Arc<dyn Hasher>,
        crypto: Arc<dyn Crypto>,
        uid: Arc<dyn Generator>,
        token: Arc<dyn TokenManager>,
        mail: Arc<dyn Mailer>,
        oauth: OAuthManager,
        session: Arc<dyn SessionRepository>,
        repo: Arc<dyn AuthRepository>,
    ) -> Self {
        Self { config, hasher, crypto, uid, token, mail, session, oauth, repo }
    }

    /// Validates user credentials and returns the authenticated user
    async fn authenticate_user(&self, email: &str, password: &str) -> Result<User, AppError> {
        let user = self
            .repo
            .find_user_by_email(email)
            .await?
            .ok_or_else(|| AppError::Unauthorized(INVALID_CREDENTIALS_MSG.to_string()))?;

        // Check account status
        if user.status != UserStatus::Active {
            return Err(AppError::Forbidden(INACTIVE_ACCOUNT_MSG.to_string()));
        }

        // Verify password
        let credential = self
            .repo
            .find_user_credential_by_user_id(user.id)
            .await?
            .ok_or_else(|| AppError::Unauthorized(INVALID_CREDENTIALS_MSG.to_string()))?;

        if !self.hasher.verify(password, &credential.password)? {
            return Err(AppError::Unauthorized(INVALID_CREDENTIALS_MSG.to_string()));
        }

        Ok(user)
    }

    /// Creates and stores a refresh token session
    async fn create_token_session(&self, user_id: i64) -> Result<(String, String), AppError> {
        let access_token = self.token.create_access_token(user_id)?;
        let refresh_token = self.token.create_refresh_token(user_id)?;

        // Store refresh token in session
        let claims = self.token.validate_refresh_token(&refresh_token)?;
        let ttl = (claims.exp - claims.iat) as u64;
        self.session.add_token(&claims.jti, ttl).await?;

        Ok((access_token, refresh_token))
    }

    /// Validates TOTP code against user's MFA factors
    async fn validate_totp_code(&self, user_id: i64, mfa_code: &str) -> Result<bool, AppError> {
        let mfa_factors = self.repo.find_mfa_factors_by_user_id(user_id).await?;

        if mfa_factors.is_empty() {
            return Err(AppError::Forbidden(MFA_NOT_ENABLED_MSG.to_string()));
        }

        for factor in mfa_factors
            .iter()
            .filter(|f| f.mfa_type == MfaFactorType::Totp && f.is_verified)
        {
            if self.verify_totp_factor(factor, mfa_code)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Verifies a single TOTP factor
    fn verify_totp_factor(&self, factor: &MfaFactor, code: &str) -> Result<bool, AppError> {
        let decrypted_secret_base64 = self.crypto.decrypt(&factor.secret)?;
        let secret_bytes = general_purpose::STANDARD.decode(&decrypted_secret_base64).map_err(|er| {
            tracing::error!("error decoding base64 secret: {}", er);
            AppError::Internal
        })?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            TOTP_DIGITS,
            TOTP_SKEW,
            TOTP_STEP,
            secret_bytes,
            Some(self.config.get::<String>("jwt.issuer")?),
            factor.friendly_name.clone().unwrap_or("default".into()),
        )?;

        // Use current timestamp for more precise validation
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        Ok(totp.check(code, timestamp))
    }

    /// Rotates refresh token for security
    async fn rotate_refresh_token(&self, old_token: &str) -> Result<RefreshTokenOutput, AppError> {
        let claims = self.token.validate_refresh_token(old_token)?;

        // Check if token is whitelisted
        if !self.session.has_token(&claims.jti).await? {
            // Token rotation attack detection - invalidate all user sessions
            // TODO: change to actual user_id
            self.invalidate_all_user_sessions(1).await?;
            return Err(AppError::Unauthorized(INVALID_REFRESH_TOKEN_MSG.to_string()));
        }

        // Remove old token
        self.session.delete_token(&claims.jti).await?;

        // Create new tokens
        let (access_token, refresh_token) = self.create_token_session(claims.sub).await?;

        Ok(RefreshTokenOutput { access_token, refresh_token })
    }

    /// Invalidates all sessions for a user (security measure)
    async fn invalidate_all_user_sessions(&self, user_id: u64) -> Result<(), AppError> {
        // This would require a method to get all sessions for a user
        // For now, we'll log this as a security event
        tracing::warn!("Potential token rotation attack detected for user {}", user_id);
        // TODO: Implement actual session invalidation
        Ok(())
    }

    /// Builds OAuth user profile with proper name handling
    fn build_oauth_user_profile(&self, user_profile: OAuthUserData, provider: String) -> OAuthUserProfile {
        let name = user_profile
            .name
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| user_profile.email.clone());

        OAuthUserProfile {
            email: user_profile.email,
            name,
            avatar_url: user_profile.avatar_url,
            provider_user_id: user_profile.provider_user_id,
            provider,
        }
    }
}

#[async_trait]
impl AuthnUseCase for AuthnService {
    async fn login(&self, input: LoginInput) -> Result<LoginOutput, AppError> {
        input.validate()?;

        let user = self.authenticate_user(&input.email, &input.password).await?;

        // Check for MFA requirements
        let mfa_factors = self.repo.find_mfa_factors_by_user_id(user.id).await?;

        // Only require MFA if there are verified factors
        let requires_mfa = mfa_factors.iter().any(|f| f.is_verified);

        if requires_mfa {
            let pre_auth_token = self.token.create_generic_token(user.id)?;
            return Ok(LoginOutput::MfaRequired { mfa_required: true, pre_auth_token });
        }

        let (access_token, refresh_token) = self.create_token_session(user.id).await?;

        Ok(LoginOutput::Success { access_token, refresh_token })
    }

    async fn register(&self, input: RegisterInput) -> Result<RegisterOutput, AppError> {
        input.validate()?;

        if self.repo.find_user_by_email(&input.email).await?.is_some() {
            return Err(AppError::Conflict(EMAIL_EXISTS_MSG.to_string()));
        }

        let token = Uuid::new_v4().to_string();
        let new_user = NewUser {
            id: self.uid.generate()?,
            email: input.email.trim().to_lowercase(),
            full_name: input.full_name,
            status: UserStatus::Unverified,
            password: self.hasher.hash(&input.password)?,
            verify_token: token.clone(),
            verify_expiry: Utc::now() + Duration::hours(1),
        };

        self.repo.create_new_user(&new_user).await?;

        let email = Email::build_signup_verification(
            new_user.email.as_str(),
            new_user.full_name.as_str(),
            &format!("http://localhost:8000/auth/verify-email?token={token}"),
        );

        self.mail.send(email).await?;

        Ok(RegisterOutput { success: true, message: VERIFICATION_MSG.to_string() })
    }

    async fn verify_email(&self, input: VerifyEmailInput) -> Result<VerifyEmailOutput, AppError> {
        input.validate()?;

        let user_verify_data = self.repo.find_user_verification_by_token(&input.token).await?;
        if user_verify_data.is_none() {
            return Err(AppError::Forbidden("Invalid or expired token".into()));
        }

        let user_verify = user_verify_data.unwrap();
        if user_verify.expires_at < chrono::Utc::now() {
            return Err(AppError::Forbidden("Verification token has expired".into()));
        }

        self.repo
            .verify_user_and_delete_token(user_verify.user_id, &user_verify.token)
            .await?;

        Ok(VerifyEmailOutput { redirect: format!("{}?state=verify_email", self.config.get::<String>("redirect_to")?) })
    }

    async fn logout(&self, input: LogoutInput) -> Result<LogoutOutput, AppError> {
        input.validate()?;

        let claims = self.token.validate_refresh_token(&input.refresh_token)?;
        self.session.delete_token(&claims.jti).await?;

        Ok(LogoutOutput { success: true })
    }

    async fn refresh_token(&self, input: RefreshTokenInput) -> Result<RefreshTokenOutput, AppError> {
        input.validate()?;

        self.rotate_refresh_token(&input.refresh_token).await
    }

    async fn login_2fa(&self, input: Login2faInput) -> Result<Login2faOutput, AppError> {
        input.validate()?;

        let claims = self.token.validate_generic_token(&input.pre_auth_token)?;

        if !self.validate_totp_code(claims.sub, &input.mfa_code).await? {
            return Err(AppError::Unauthorized(INVALID_MFA_CODE_MSG.to_string()));
        }

        let (access_token, refresh_token) = self.create_token_session(claims.sub).await?;

        Ok(Login2faOutput { access_token, refresh_token })
    }

    async fn oauth_login(&self, input: OAuthLoginInput) -> Result<OAuthLoginOutput, AppError> {
        input.validate()?;

        let oauth_provider = self.oauth.get_provider(&input.provider)?;

        let auth_detail = oauth_provider.get_authorization_details();

        Ok(OAuthLoginOutput {
            auth_url: auth_detail.url,
            csrf_token: auth_detail.csrf_token,
            pkce_verifier: auth_detail.pkce_verifier,
        })
    }

    async fn oauth_callback(&self, input: OAuthCallbackInput) -> Result<OAuthCallbackOutput, AppError> {
        input.validate()?;

        let oauth_provider = self.oauth.get_provider(&input.provider)?;

        let provider_access_token = oauth_provider.exchange_code(input.code, input.pkce_verifier_secret).await?;

        let user_profile = oauth_provider.get_user_profile(&provider_access_token).await?;
        let oauth_user_profile = self.build_oauth_user_profile(user_profile, input.provider);

        let user = self.repo.find_or_create_oauth_user(oauth_user_profile).await?;

        let (access_token, refresh_token) = self.create_token_session(user.id).await?;

        Ok(OAuthCallbackOutput { access_token, refresh_token })
    }
}
