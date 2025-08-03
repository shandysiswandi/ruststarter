use crate::auth::domain::user::User;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct ListUsersRequest {
    #[serde(default = "default_page")]
    pub page: u64,
    #[serde(default = "default_per_page")]
    pub per_page: u64,
}

fn default_page() -> u64 {
    1
}

fn default_per_page() -> u64 {
    10
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: i64,
    pub email: String,
    pub full_name: String,
    pub avatar_url: Option<String>,
    pub status: String,
}

impl From<User> for UserResponse {
    fn from(output: User) -> Self {
        Self {
            id: output.id,
            email: output.email,
            full_name: output.full_name,
            avatar_url: Some(output.avatar),
            status: output.status.to_string(),
        }
    }
}
