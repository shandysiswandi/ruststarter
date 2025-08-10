use std::sync::Arc;

use app_core::error::AppError;
use async_trait::async_trait;
use validator::Validate;

use crate::domain::entity::user::{User, UserUpdatePayload};
use crate::domain::inout::prelude::*;
use crate::outbound::repository::AuthRepository;

#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait AuthzUseCase: Send + Sync {
    async fn list_users(&self, input: ListUsersInput) -> Result<ListUsersOutput, AppError>;
    async fn get_user(&self, input: GetUserInput) -> Result<User, AppError>;
    async fn update_user(&self, input: UpdateUserInput) -> Result<UpdateUserOutput, AppError>;
    async fn set_user_roles(&self, input: SetUserRolesInput) -> Result<SetUserRolesOutput, AppError>;
}

#[derive(Clone)]
pub struct AuthzService {
    repo: Arc<dyn AuthRepository>,
}

impl AuthzService {
    pub fn new(repo: Arc<dyn AuthRepository>) -> Self {
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

    async fn get_user(&self, input: GetUserInput) -> Result<User, AppError> {
        input.validate()?;

        self.repo
            .find_user_by_id(input.user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))
    }

    async fn update_user(&self, input: UpdateUserInput) -> Result<UpdateUserOutput, AppError> {
        input.validate()?;

        self.repo
            .update_user(UserUpdatePayload {
                id: input.id,
                email: input.email,
                full_name: input.full_name,
                status: input.status,
                avatar_url: None,
            })
            .await?;

        Ok(UpdateUserOutput { success: true })
    }

    async fn set_user_roles(&self, input: SetUserRolesInput) -> Result<SetUserRolesOutput, AppError> {
        input.validate()?;

        if self.repo.find_user_by_id(input.user_id).await?.is_none() {
            return Err(AppError::NotFound("User not found".into()));
        }

        if !self.repo.roles_exist(&input.role_ids).await? {
            return Err(AppError::ValidationStr("One or more provided role IDs are invalid".to_string()));
        }

        self.repo.set_user_roles(input.user_id, input.role_ids).await?;

        Ok(SetUserRolesOutput { success: true })
    }
}
