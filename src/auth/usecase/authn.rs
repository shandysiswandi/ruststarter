use crate::app::error::AppError;
use crate::app::jwt::TokenManager;
use crate::app::oauthold::OAuthManager;
use crate::app::password::Hasher;
use crate::app::uid::Generator;
use crate::auth::domain::authn::{
    Login2faInput, Login2faOutput, LoginInput, LoginOutput, LogoutInput, LogoutOutput, OAuthCallbackInput,
    OAuthCallbackOutput, OAuthLoginInput, OAuthLoginOutput, RefreshTokenInput, RefreshTokenOutput,
    RegisterInput, RegisterOutput,
};
use crate::auth::domain::mfa::MfaFactorType;
use crate::auth::domain::user::{OAuthUserProfile, User, UserStatus};
use crate::auth::outbound::session::SessionRepository;
use crate::auth::outbound::sql::AuthDataSource;
use async_trait::async_trait;
use std::sync::Arc;
use totp_rs::{Algorithm, Secret, TOTP};
use validator::Validate;

#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait AuthnUseCase: Send + Sync {
    async fn login(&self, input: LoginInput) -> Result<LoginOutput, AppError>;
    async fn register(&self, input: RegisterInput) -> Result<RegisterOutput, AppError>;
    async fn logout(&self, input: LogoutInput) -> Result<LogoutOutput, AppError>;
    async fn refresh_token(&self, input: RefreshTokenInput) -> Result<RefreshTokenOutput, AppError>;
    async fn login_2fa(&self, input: Login2faInput) -> Result<Login2faOutput, AppError>;
    async fn oauth_login(&self, input: OAuthLoginInput) -> Result<OAuthLoginOutput, AppError>;
    async fn oauth_callback(&self, input: OAuthCallbackInput) -> Result<OAuthCallbackOutput, AppError>;
}

#[derive(Clone)]
pub struct AuthnService {
    hasher: Arc<dyn Hasher>,
    uid: Arc<dyn Generator>,
    token: Arc<dyn TokenManager>,
    session: Arc<dyn SessionRepository>,
    oauth: OAuthManager,
    auth_repo: Arc<dyn AuthDataSource>,
}

impl AuthnService {
    pub fn new(
        hasher: Arc<dyn Hasher>,
        uid: Arc<dyn Generator>,
        token: Arc<dyn TokenManager>,
        session: Arc<dyn SessionRepository>,
        oauth: OAuthManager,
        auth_repo: Arc<dyn AuthDataSource>,
    ) -> Self {
        Self {
            hasher,
            uid,
            token,
            session,
            oauth,
            auth_repo,
        }
    }
}

#[async_trait]
impl AuthnUseCase for AuthnService {
    async fn login(&self, input: LoginInput) -> Result<LoginOutput, AppError> {
        input.validate()?;

        let user = self
            .auth_repo
            .find_user_by_email(&input.email)
            .await?
            .ok_or_else(|| AppError::Unauthorized("Invalid email or password".to_string()))?;

        if user.status != UserStatus::Active {
            return Err(AppError::Forbidden(
                "Your account is not active. Please verify your email or contact support.".to_string(),
            ));
        }

        self.hasher
            .verify(&input.password, &user.password)?
            .then_some(())
            .ok_or_else(|| AppError::Unauthorized("Invalid email or password".to_string()))?;

        let mfa_factors = self.auth_repo.find_mfa_factors_by_user_id(user.id).await?;
        if !mfa_factors.is_empty() {
            let pre_auth_token = self.token.create_generic_token(user.id)?;

            return Ok(LoginOutput::MfaRequired {
                mfa_required: true,
                pre_auth_token,
            });
        }

        // Issue a pair of tokens.
        let access_token = self.token.create_access_token(user.id)?;
        let refresh_token = self.token.create_refresh_token(user.id)?;

        // Whitelist the refresh token.
        let claims = self.token.validate_refresh_token(&refresh_token)?;
        let exp = (claims.exp - claims.iat) as u64;
        self.session.add_token(&claims.jti, exp).await?;

        Ok(LoginOutput::Success {
            access_token,
            refresh_token,
        })
    }

    async fn register(&self, input: RegisterInput) -> Result<RegisterOutput, AppError> {
        input.validate()?;

        if self.auth_repo.find_user_by_email(&input.email).await?.is_some() {
            return Err(AppError::Conflict(
                "A user with this email already exists".to_string(),
            ));
        }

        let hashed_password = self.hasher.hash(&input.password)?;
        let user_id = self.uid.generate()?;

        let user = User {
            id: user_id,
            full_name: input.full_name,
            email: input.email,
            status: UserStatus::Unverified,
            password: hashed_password,
        };

        self.auth_repo.create_user(user).await?;

        // TODO: In a real application, you might send a verification email here.
        Ok(RegisterOutput {
            success: true,
            message: "Please verify your email to activate your account.".to_string(),
        })
    }

    async fn logout(&self, input: LogoutInput) -> Result<LogoutOutput, AppError> {
        input.validate()?;

        let claims = self.token.validate_refresh_token(&input.refresh_token)?;

        self.session.delete_token(&claims.jti).await?;

        Ok(LogoutOutput { success: true })
    }

    async fn refresh_token(&self, input: RefreshTokenInput) -> Result<RefreshTokenOutput, AppError> {
        input.validate()?;

        // Validate the refresh token's signature and claims.
        let claims = self.token.validate_refresh_token(&input.refresh_token)?;

        // Check if the token is in our whitelist.
        if !self.session.has_token(&claims.jti).await? {
            // If the token is not in the whitelist, it means it has either been used
            // before or was never valid. This is a potential sign of a stolen token.
            // TODO: In a real app, you would invalidate all tokens for this user.
            return Err(AppError::Unauthorized("Invalid refresh token".to_string()));
        }

        // Invalidate the used refresh token immediately.
        self.session.delete_token(&claims.jti).await?;

        // Issue a new pair of tokens.
        let access_token = self.token.create_access_token(claims.sub)?;
        let refresh_token = self.token.create_refresh_token(claims.sub)?;

        // Whitelist the new refresh token.
        let new_claims = self.token.validate_refresh_token(&refresh_token)?;
        let exp = (new_claims.exp - new_claims.iat) as u64;
        self.session.add_token(&new_claims.jti, exp).await?;

        Ok(RefreshTokenOutput {
            access_token,
            refresh_token,
        })
    }

    async fn login_2fa(&self, input: Login2faInput) -> Result<Login2faOutput, AppError> {
        input.validate()?;

        let claims = self.token.validate_access_token(&input.pre_auth_token)?;

        let mfa_factors = self.auth_repo.find_mfa_factors_by_user_id(claims.sub).await?;
        if mfa_factors.is_empty() {
            return Err(AppError::Forbidden(
                "MFA is not enabled for this user.".to_string(),
            ));
        }

        let mut is_mfa_valid = false;
        for factor in mfa_factors.iter().filter(|f| f.mfa_type == MfaFactorType::Totp) {
            let secret_bytes = Secret::Encoded(factor.secret.clone())
                .to_bytes()
                .unwrap_or_default();

            if let Ok(totp) = TOTP::new(
                Algorithm::SHA1,
                6,
                1,
                30,
                secret_bytes,
                Some(factor.friendly_name.clone()),
                "account@github.com".to_string(),
            ) {
                if let Ok(valid) = totp.check_current(&input.mfa_code) {
                    is_mfa_valid = valid;
                    break;
                }
            }
        }

        if !is_mfa_valid {
            return Err(AppError::Unauthorized("Invalid MFA code".to_string()));
        }

        let access_token = self.token.create_access_token(claims.sub)?;
        let refresh_token = self.token.create_refresh_token(claims.sub)?;

        Ok(Login2faOutput {
            access_token,
            refresh_token,
        })
    }

    async fn oauth_login(&self, input: OAuthLoginInput) -> Result<OAuthLoginOutput, AppError> {
        input.validate()?;

        let oauth_provider = self
            .oauth
            .get_provider(&input.provider)
            .ok_or_else(|| AppError::NotFound(format!("OAuth provider '{}' not found", input.provider)))?;

        let auth_detail = oauth_provider.get_authorization_details();

        Ok(OAuthLoginOutput {
            auth_url: auth_detail.url,
            csrf_token: auth_detail.csrf_token,
            pkce_verifier: auth_detail.pkce_verifier,
        })
    }

    async fn oauth_callback(&self, input: OAuthCallbackInput) -> Result<OAuthCallbackOutput, AppError> {
        input.validate()?;

        let oauth_provider = self
            .oauth
            .get_provider(&input.provider)
            .ok_or_else(|| AppError::NotFound(format!("OAuth provider '{}' not found", input.provider)))?;

        let provider_access_token = oauth_provider
            .exchange_code(input.code, input.pkce_verifier_secret)
            .await?;

        let user_profile = oauth_provider.get_user_profile(&provider_access_token).await?;

        let user = self
            .auth_repo
            .find_or_create_oauth_user(OAuthUserProfile {
                email: user_profile.email,
                name: user_profile.name,
                avatar_url: user_profile.avatar_url,
            })
            .await?;

        let access_token = self.token.create_access_token(user.id)?;
        let refresh_token = self.token.create_refresh_token(user.id)?;

        let claims = self.token.validate_refresh_token(&refresh_token)?;
        let exp = (claims.exp - claims.iat) as u64;
        self.session.add_token(&claims.jti, exp).await?;

        Ok(OAuthCallbackOutput {
            access_token,
            refresh_token,
        })
    }
}
