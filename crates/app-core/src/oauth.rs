//! A utility module for handling OAuth 2.0 flows with PKCE.

use std::collections::HashMap;
use std::sync::Arc;

use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    RevocationUrl, Scope, StandardRevocableToken, TokenResponse, TokenUrl,
};
use reqwest::{Client, ClientBuilder, redirect};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum OAuthError {
    #[error("Invalid URL format: {0}")]
    InvalidUrl(#[from] oauth2::url::ParseError),

    #[error("HTTP client error: {0}")]
    HttpClient(#[from] reqwest::Error),

    #[error("OAuth token exchange failed: {0}")]
    TokenExchange(String),

    #[error("Failed to parse user profile response")]
    ProfileParse,

    #[error("Token revocation failed: {0}")]
    TokenRevocation(String),

    #[error("Provider not found: {0}")]
    ProviderNotFound(String),

    #[error("Internal error occurred")]
    Internal,
}

pub struct AuthorizationDetails {
    pub url: String,
    pub csrf_token: CsrfToken,
    pub pkce_verifier: PkceCodeVerifier,
}

#[derive(Deserialize, Debug)]
pub struct OAuthUserProfile {
    pub provider_user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

#[async_trait::async_trait]
#[cfg_attr(feature = "testing", mockall::automock)]
pub trait OAuthProvider: Send + Sync {
    /// Generates the authorization URL and the necessary state for the PKCE
    /// flow.
    fn get_authorization_details(&self) -> AuthorizationDetails;

    /// Exchanges an authorization code for an access token.
    async fn exchange_code(&self, code: String, pkce_verifier_secret: String) -> Result<String, OAuthError>;

    /// Fetches the user's profile from the provider using an access token.
    async fn get_user_profile(&self, access_token: &str) -> Result<OAuthUserProfile, OAuthError>;

    /// Revokes a token with the provider.
    async fn revoke_token(&self, token: String) -> Result<(), OAuthError>;
}

#[derive(Debug)]
pub struct GoogleOAuthProvider {
    client_id: ClientId,
    client_secret: ClientSecret,
    auth_url: AuthUrl,
    token_url: TokenUrl,
    redirect_url: RedirectUrl,
    revocation_url: RevocationUrl,
}

impl GoogleOAuthProvider {
    pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Result<Self, OAuthError> {
        Ok(Self {
            client_id: ClientId::new(client_id),
            client_secret: ClientSecret::new(client_secret),
            auth_url: AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())?,
            token_url: TokenUrl::new("https://oauth2.googleapis.com/token".to_string())?,
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

        tracing::info!("Generated authorization URL: {:?}", auth_url);
        tracing::info!("PKCE verifier created");

        AuthorizationDetails { url: auth_url.to_string(), csrf_token, pkce_verifier }
    }

    async fn exchange_code(&self, code: String, pkce_verifier_secret: String) -> Result<String, OAuthError> {
        let http_client = ClientBuilder::new().redirect(redirect::Policy::none()).build().map_err(|e| {
            tracing::error!("Failed to build HTTP client: {:?}", e);
            OAuthError::HttpClient(e)
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
                let error_msg = match &e {
                    oauth2::RequestTokenError::ServerResponse(err) => {
                        format!("Server response error: {:?}", err.error_description())
                    },
                    oauth2::RequestTokenError::Parse(_, body) => {
                        if let Ok(body_str) = std::str::from_utf8(body) {
                            format!("Parse error. Response body: {}", body_str)
                        } else {
                            "Parse error with non-UTF8 response".to_string()
                        }
                    },
                    _ => format!("Token exchange error: {:?}", e),
                };
                tracing::error!("OAuth token exchange failed: {}", error_msg);
                OAuthError::TokenExchange(error_msg)
            })?;

        Ok(token_result.access_token().secret().to_string())
    }

    async fn get_user_profile(&self, access_token: &str) -> Result<OAuthUserProfile, OAuthError> {
        let user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo";
        let client = Client::new();

        #[derive(Deserialize)]
        struct GoogleProfile {
            sub: String, // Google's user ID field
            email: String,
            name: Option<String>,
            picture: Option<String>,
        }

        let profile: GoogleProfile = client
            .get(user_info_url)
            .bearer_auth(access_token)
            .send()
            .await?
            .json()
            .await
            .map_err(|_| OAuthError::ProfileParse)?;

        Ok(OAuthUserProfile {
            provider_user_id: profile.sub,
            email: profile.email,
            name: profile.name,
            avatar_url: profile.picture,
        })
    }

    async fn revoke_token(&self, token: String) -> Result<(), OAuthError> {
        let http_client = ClientBuilder::new().redirect(redirect::Policy::none()).build().map_err(|e| {
            tracing::error!("Failed to build HTTP client for revocation: {:?}", e);
            OAuthError::HttpClient(e)
        })?;

        BasicClient::new(self.client_id.clone())
            .set_client_secret(self.client_secret.clone())
            .set_auth_uri(self.auth_url.clone())
            .set_token_uri(self.token_url.clone())
            .set_redirect_uri(self.redirect_url.clone())
            .set_revocation_url(self.revocation_url.clone())
            .revoke_token(StandardRevocableToken::AccessToken(oauth2::AccessToken::new(token)))
            .map_err(|e| {
                let error_msg = format!("Token revocation configuration error: {:?}", e);
                tracing::error!("{}", error_msg);
                OAuthError::TokenRevocation(error_msg)
            })?
            .request_async(&http_client)
            .await
            .map_err(|e| {
                let error_msg = format!("Token revocation request failed: {:?}", e);
                tracing::error!("{}", error_msg);
                OAuthError::TokenRevocation(error_msg)
            })?;

        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct OAuthManager {
    providers: HashMap<String, Arc<dyn OAuthProvider>>,
}

impl OAuthManager {
    pub fn new() -> Self {
        Self { providers: HashMap::new() }
    }

    pub fn add_provider(&mut self, name: &str, provider: Arc<dyn OAuthProvider>) {
        self.providers.insert(name.to_string(), provider);
    }

    pub fn get_provider(&self, name: &str) -> Result<&Arc<dyn OAuthProvider>, OAuthError> {
        self.providers
            .get(name)
            .ok_or_else(|| OAuthError::ProviderNotFound(name.to_string()))
    }

    pub fn has_provider(&self, name: &str) -> bool {
        self.providers.contains_key(name)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use mockall::predicate::*;

    use super::*;

    #[test]
    fn test_oauth_manager() {
        let mut manager = OAuthManager::new();
        let provider = Arc::new(MockOAuthProvider::new());

        manager.add_provider("test", provider);

        assert!(manager.has_provider("test"));

        let result = manager.get_provider("test");
        assert!(result.is_ok());

        let result = manager.get_provider("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_google_oauth_provider_invalid_redirect_url() {
        let provider =
            GoogleOAuthProvider::new("client_id".to_string(), "client_secret".to_string(), "invalid_url".to_string());

        assert!(provider.is_err());
        assert!(matches!(provider.unwrap_err(), OAuthError::InvalidUrl(_)));
    }

    #[test]
    fn test_google_oauth_provider_authorization_details() {
        let provider = GoogleOAuthProvider::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "https://example.com/callback".to_string(),
        )
        .unwrap();

        let details = provider.get_authorization_details();

        assert!(details.url.starts_with("https://accounts.google.com/o/oauth2/v2/auth"));
        assert!(details.url.contains("response_type=code"));
        assert!(details.url.contains("client_id=client_id"));
        assert!(details.url.contains("code_challenge_method=S256"));
        assert!(details.url.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"));
        assert!(details.url.contains("scope=openid+email+profile"));
        assert!(details.url.contains("response_type=code"));
    }

    #[tokio::test]
    async fn test_google_oauth_provider_successful_flow() {
        let mut mock_provider = MockOAuthProvider::new();

        // Set up expectations
        mock_provider.expect_get_authorization_details().returning(|| {
            let (_, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
            AuthorizationDetails {
                url: "https://example.com/auth".to_string(),
                csrf_token: CsrfToken::new("test_csrf_token".to_string()),
                pkce_verifier,
            }
        });

        mock_provider
            .expect_exchange_code()
            .with(eq("test_code".to_string()), eq("test_verifier".to_string()))
            .returning(|_, _| Box::pin(async move { Ok("mock_access_token".to_string()) }));

        mock_provider.expect_get_user_profile().with(eq("mock_token")).returning(|_| {
            Box::pin(async move {
                Ok(OAuthUserProfile {
                    provider_user_id: "123456".to_string(),
                    email: "test@example.com".to_string(),
                    name: Some("Test User".to_string()),
                    avatar_url: Some("https://example.com/avatar.jpg".to_string()),
                })
            })
        });

        mock_provider
            .expect_revoke_token()
            .with(eq("mock_token".to_string()))
            .returning(|_| Box::pin(async move { Ok(()) }));

        // Test authorization details
        let auth_details = mock_provider.get_authorization_details();
        assert_eq!(auth_details.url, "https://example.com/auth");

        // Test successful code exchange
        let token_result = mock_provider
            .exchange_code("test_code".to_string(), "test_verifier".to_string())
            .await;
        assert!(token_result.is_ok());
        assert_eq!(token_result.unwrap(), "mock_access_token");

        // Test successful profile fetch
        let profile_result = mock_provider.get_user_profile("mock_token").await;
        assert!(profile_result.is_ok());
        let profile = profile_result.unwrap();
        assert_eq!(profile.provider_user_id, "123456");
        assert_eq!(profile.email, "test@example.com");
        assert_eq!(profile.name, Some("Test User".to_string()));

        // Test successful token revocation
        let revoke_result = mock_provider.revoke_token("mock_token".to_string()).await;
        assert!(revoke_result.is_ok());
    }

    #[tokio::test]
    async fn test_google_oauth_provider_failure_flow() {
        let mut mock_provider = MockOAuthProvider::new();

        // Set up expectations for failures
        mock_provider
            .expect_exchange_code()
            .with(
                mockall::predicate::eq("test_code".to_string()),
                mockall::predicate::eq("test_verifier".to_string()),
            )
            .returning(|_, _| {
                Box::pin(async move { Err(OAuthError::TokenExchange("Mock exchange failure".to_string())) })
            });

        mock_provider
            .expect_get_user_profile()
            .with(mockall::predicate::eq("mock_token"))
            .returning(|_| Box::pin(async move { Err(OAuthError::ProfileParse) }));

        mock_provider
            .expect_revoke_token()
            .with(mockall::predicate::eq("mock_token".to_string()))
            .returning(|_| {
                Box::pin(async move { Err(OAuthError::TokenRevocation("Mock revocation failure".to_string())) })
            });

        // Test failed code exchange
        let token_result = mock_provider
            .exchange_code("test_code".to_string(), "test_verifier".to_string())
            .await;
        assert!(token_result.is_err());
        assert!(matches!(token_result.unwrap_err(), OAuthError::TokenExchange(_)));

        // Test failed profile fetch
        let profile_result = mock_provider.get_user_profile("mock_token").await;
        assert!(profile_result.is_err());
        assert!(matches!(profile_result.unwrap_err(), OAuthError::ProfileParse));

        // Test failed token revocation
        let revoke_result = mock_provider.revoke_token("mock_token".to_string()).await;
        assert!(revoke_result.is_err());
        assert!(matches!(revoke_result.unwrap_err(), OAuthError::TokenRevocation(_)));
    }
}
