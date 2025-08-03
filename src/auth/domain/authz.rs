use validator::Validate;

use crate::auth::domain::user::User;

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
    pub total: i64,
}
