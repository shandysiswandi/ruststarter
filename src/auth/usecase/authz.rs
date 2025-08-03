use crate::app::error::AppError;
use crate::auth::domain::authz::{ListUsersInput, ListUsersOutput};
use crate::auth::outbound::sql::AuthDataSource;
use async_trait::async_trait;
use std::sync::Arc;
use validator::Validate;

#[async_trait]
pub trait AuthzUseCase: Send + Sync {
    async fn list_users(&self, input: ListUsersInput) -> Result<ListUsersOutput, AppError>;
}

#[derive(Clone)]
pub struct AuthzService {
    repo: Arc<dyn AuthDataSource>,
}

impl AuthzService {
    pub fn new(repo: Arc<dyn AuthDataSource>) -> Self {
        Self { repo }
    }
}

#[async_trait]
impl AuthzUseCase for AuthzService {
    async fn list_users(&self, input: ListUsersInput) -> Result<ListUsersOutput, AppError> {
        input.validate()?;

        let (users, total) = self
            .repo
            .find_all_users((input.page - 1) * input.per_page, input.per_page)
            .await?;

        Ok(ListUsersOutput { users, total })
    }
}
