//

use oauth2::{CsrfToken, PkceCodeVerifier};

//
#[derive(Debug, Clone)]
pub struct OAuthCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

#[derive(Debug)]
pub struct AuthorizationDetails {
    pub url: String,
    pub csrf_token: CsrfToken,
    pub pkce_verifier: PkceCodeVerifier,
    pub state_id: String,
}

#[derive(Debug, Clone)]
pub struct OAuthUserProfile {
    pub provider: String,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub verified_email: bool,
}
