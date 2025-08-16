use validator::Validate;

use super::super::entity::user::{User, UserStatus};

// ╔════════════════════════════╗
// ║        List Users          ║
// ╚════════════════════════════╝

#[derive(Validate)]
pub struct ListUsersInput {
    #[validate(range(min = 1))]
    pub page: u64,

    #[validate(range(min = 1, max = 100))]
    pub per_page: u64,
}

#[derive(Debug)]
pub struct ListUsersOutput {
    pub users: Vec<User>,
    pub total: u64,
}

// ╔════════════════════════════╗
// ║         Get User           ║
// ╚════════════════════════════╝

#[derive(Validate)]
pub struct GetUserInput {
    #[validate(range(min = 1))]
    pub user_id: i64,
}

// ╔════════════════════════════╗
// ║       Update User          ║
// ╚════════════════════════════╝

#[derive(Validate)]
pub struct UpdateUserInput {
    #[validate(range(min = 1))]
    pub id: i64,
    pub email: Option<String>,
    pub full_name: Option<String>,
    pub status: Option<UserStatus>,
}

#[derive(Debug)]
pub struct UpdateUserOutput {
    pub success: bool,
}

// ╔════════════════════════════╗
// ║       Set User Roles       ║
// ╚════════════════════════════╝

#[derive(Validate)]
pub struct SetUserRolesInput {
    pub user_id: i64,
    pub role_ids: Vec<i64>,
}

pub struct SetUserRolesOutput {
    pub success: bool,
}
