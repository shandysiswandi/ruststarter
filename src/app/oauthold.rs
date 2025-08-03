//! A utility module for handling OAuth 2.0 flows with PKCE.

use crate::app::error::AppError;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, RevocationUrl, Scope, StandardRevocableToken, TokenResponse, TokenUrl, basic::BasicClient,
};
use reqwest::{Client, ClientBuilder, redirect};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

/// Contains the details needed to initiate an authorization redirect.
pub struct AuthorizationDetails {
    pub url: String,
    pub csrf_token: CsrfToken,
    pub pkce_verifier: PkceCodeVerifier,
}

/// A generic representation of user information fetched from an OAuth provider.
#[derive(Deserialize, Debug)]
pub struct OAuthUserProfile {
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

/// A trait defining the contract for an OAuth 2.0 provider.
#[async_trait::async_trait]
pub trait OAuthProvider: Send + Sync {
    /// Generates the authorization URL and the necessary state for the PKCE flow.
    fn get_authorization_details(&self) -> AuthorizationDetails;

    /// Exchanges an authorization code for an access token.
    async fn exchange_code(&self, code: String, pkce_verifier_secret: String) -> Result<String, AppError>;

    /// Fetches the user's profile from the provider using an access token.
    async fn get_user_profile(&self, access_token: &str) -> Result<OAuthUserProfile, AppError>;

    /// Revokes a token with the provider.
    async fn revoke_token(&self, token: String) -> Result<(), AppError>;
}

/// A concrete implementation of `OAuthProvider` for Google.
pub struct GoogleOAuthProvider {
    client_id: ClientId,
    client_secret: ClientSecret,
    auth_url: AuthUrl,
    token_url: TokenUrl,
    redirect_url: RedirectUrl,
    revocation_url: RevocationUrl,
}

impl GoogleOAuthProvider {
    pub fn new(
        client_id: String,
        client_secret: String,
        redirect_uri: String,
    ) -> Result<Self, oauth2::url::ParseError> {
        Ok(Self {
            client_id: ClientId::new(client_id),
            client_secret: ClientSecret::new(client_secret),
            auth_url: AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())?,
            token_url: TokenUrl::new("https://oauth2.googleapis.com/v3/token".to_string())?,
            redirect_url: RedirectUrl::new(redirect_uri)?,
            revocation_url: RevocationUrl::new("https://oauth2.googleapis.com/revoke".to_string())?,
        })
    }
}

#[async_trait::async_trait]
impl OAuthProvider for GoogleOAuthProvider {
    fn get_authorization_details(&self) -> AuthorizationDetails {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token) = BasicClient::new(self.client_id.clone())
            .set_client_secret(self.client_secret.clone())
            .set_auth_uri(self.auth_url.clone())
            .set_token_uri(self.token_url.clone())
            .set_redirect_uri(self.redirect_url.clone())
            .set_revocation_url(self.revocation_url.clone())
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        tracing::info!("FIRST {:?}", auth_url);
        tracing::info!("FIRST {:?}", pkce_verifier.secret());

        AuthorizationDetails {
            url: auth_url.to_string(),
            csrf_token,
            pkce_verifier,
        }
    }

    async fn exchange_code(&self, code: String, pkce_verifier_secret: String) -> Result<String, AppError> {
        let http_client = ClientBuilder::new()
            .redirect(redirect::Policy::none())
            .build()
            .map_err(|e| {
                tracing::error!("Client should build: {:?}", e);
                AppError::Internal
            })?;

        let token_result = BasicClient::new(self.client_id.clone())
            .set_client_secret(self.client_secret.clone())
            .set_auth_uri(self.auth_url.clone())
            .set_token_uri(self.token_url.clone())
            .set_redirect_uri(self.redirect_url.clone())
            .set_revocation_url(self.revocation_url.clone())
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier_secret))
            .request_async(&http_client)
            .await
            .map_err(|e| {
                if let oauth2::RequestTokenError::ServerResponse(err) = &e {
                    tracing::error!(
                        "OAuth token exchange failed with server response: {:?}",
                        err.error_description()
                    );
                } else if let oauth2::RequestTokenError::Parse(_, body) = &e {
                    if let Ok(body_str) = std::str::from_utf8(body) {
                        tracing::error!("OAuth token exchange failed. Response body: {}", body_str);
                    }
                } else {
                    tracing::error!("OAuth token exchange failed: {:?}", e);
                }

                AppError::Internal
            })?;

        Ok(token_result.access_token().secret().to_string())
    }

    async fn get_user_profile(&self, access_token: &str) -> Result<OAuthUserProfile, AppError> {
        let user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo";
        let client = Client::new();

        #[derive(Deserialize)]
        struct GoogleProfile {
            email: String,
            name: Option<String>,
            picture: Option<String>,
        }

        let profile: GoogleProfile = client
            .get(user_info_url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|_| AppError::Internal)?
            .json()
            .await
            .map_err(|_| AppError::Internal)?;

        Ok(OAuthUserProfile {
            email: profile.email,
            name: profile.name,
            avatar_url: profile.picture,
        })
    }

    async fn revoke_token(&self, token: String) -> Result<(), AppError> {
        let http_client = ClientBuilder::new()
            .redirect(redirect::Policy::none())
            .build()
            .map_err(|e| {
                tracing::error!("Client should build: {:?}", e);
                AppError::Internal
            })?;

        BasicClient::new(self.client_id.clone())
            .set_client_secret(self.client_secret.clone())
            .set_auth_uri(self.auth_url.clone())
            .set_token_uri(self.token_url.clone())
            .set_redirect_uri(self.redirect_url.clone())
            .set_revocation_url(self.revocation_url.clone())
            .revoke_token(StandardRevocableToken::AccessToken(oauth2::AccessToken::new(
                token,
            )))
            .map_err(|e| {
                tracing::error!("OAuth token revocation configuration: {:?}", e);
                AppError::Internal
            })?
            .request_async(&http_client)
            .await
            .map_err(|e| {
                tracing::error!("OAuth token revocation failed: {:?}", e);
                AppError::Internal
            })?;

        Ok(())
    }
}

/// A manager to hold all configured OAuth providers.
#[derive(Clone)]
pub struct OAuthManager {
    providers: HashMap<String, Arc<dyn OAuthProvider>>,
}

impl OAuthManager {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    pub fn add_provider(&mut self, name: &str, provider: Arc<dyn OAuthProvider>) {
        self.providers.insert(name.to_string(), provider);
    }

    pub fn get_provider(&self, name: &str) -> Option<&Arc<dyn OAuthProvider>> {
        self.providers.get(name)
    }
}
