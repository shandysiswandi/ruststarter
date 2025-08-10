#[derive(Debug, Clone)]
pub struct OAuthUserProfile {
    /// The unique identifier for the user within the OAuth provider’s system.
    pub provider_user_id: String,
    /// The name of the OAuth provider (e.g., `"google"`, `"github"`,
    /// `"facebook"`).
    pub provider: String,
    /// The user’s primary email address from the provider.
    pub email: String,
    /// The user’s display name.
    pub name: String,
    /// The user’s profile avatar URL, if available.
    pub avatar_url: Option<String>,
}
