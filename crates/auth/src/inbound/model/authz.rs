use serde::{Deserialize, Serialize};

use crate::domain::entity::user::User;

// ╔════════════════════════════╗
// ║    List Users              ║
// ╚════════════════════════════╝

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
            avatar_url: output.avatar_url,
            status: output.status.to_string(),
        }
    }
}

// ╔════════════════════════════╗
// ║    Update User             ║
// ╚════════════════════════════╝

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub full_name: Option<String>,
    pub status: Option<String>,
}

#[derive(Serialize)]
pub struct UpdateUserResponse {
    pub success: bool,
}

// ╔════════════════════════════╗
// ║    Set User Roles          ║
// ╚════════════════════════════╝

#[derive(Deserialize)]
pub struct SetUserRolesRequest {
    pub role_ids: Vec<i64>,
}

#[derive(Serialize)]
pub struct SetUserRolesResponse {
    pub success: bool,
}
