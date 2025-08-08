use std::sync::Arc;

use super::repository::AuthRepository;
use crate::{
    app::{error::AppError, uid::Generator},
    auth::domain::entity::{
        mfa::{MfaFactor, MfaFactorType},
        oauth::OAuthUserProfile,
        user::{User, UserStatus, UserUpdatePayload},
        user_connection::UserConnection,
        user_credential::UserCredential,
    },
    orm::{
        mfa_factors,
        prelude::{MfaFactors, Roles, UserConnections, UserCredentials, UserRoles, Users},
        roles, user_connections, user_credentials, user_roles, users,
    },
};
use async_trait::async_trait;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, TransactionTrait, prelude::Expr,
};

pub struct AuthORM {
    db: DatabaseConnection,
    uid: Arc<dyn Generator>,
}

impl AuthORM {
    pub fn new(db: DatabaseConnection, uid: Arc<dyn Generator>) -> Self {
        Self { db, uid }
    }

    // ----- ------ ------ ------ ------
    // Mapper from Model to Entity
    // ----- ------ ------ ------ ------

    fn to_user(&self, model: users::Model) -> User {
        User {
            id: model.id,
            email: model.email,
            full_name: model.full_name,
            avatar_url: model.avatar_url,
            status: UserStatus::from_i16(model.status),
            created_at: model.created_at.into(),
            updated_at: model.updated_at.into(),
            deleted_at: model.deleted_at.map(Into::into),
        }
    }

    fn to_user_credential(&self, model: user_credentials::Model) -> UserCredential {
        UserCredential {
            user_id: model.user_id,
            password: model.hashed_password,
            password_last_changed_at: model.password_last_changed_at.into(),
        }
    }

    fn to_user_connection(&self, model: user_connections::Model) -> UserConnection {
        UserConnection {
            id: model.id,
            user_id: model.user_id,
            provider: model.provider,
            provider_user_id: model.provider_user_id,
            access_token: model.access_token,
            refresh_token: model.refresh_token,
            expires_at: model.expires_at.map(Into::into),
            scopes: model.scopes,
            created_at: model.created_at.into(),
            updated_at: model.updated_at.into(),
        }
    }

    fn to_mfa_factor(&self, model: mfa_factors::Model) -> MfaFactor {
        MfaFactor {
            id: model.id,
            user_id: model.user_id,
            mfa_type: MfaFactorType::from_i16(model.r#type),
            friendly_name: model.friendly_name,
            secret: model.secret,
        }
    }

    // ----- ------ ------ ------ ------
    // Helper
    // ----- ------ ------ ------ ------

    async fn ensure_user_connection<C>(
        &self,
        db: &C,
        id: i64,
        user_id: i64,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<(), AppError>
    where
        C: ConnectionTrait + Send + Sync,
    {
        let exists = UserConnections::find()
            .filter(user_connections::Column::UserId.eq(user_id))
            .filter(user_connections::Column::Provider.eq(provider))
            .one(db)
            .await?;

        if exists.is_none() {
            let new_conn = user_connections::ActiveModel {
                id: ActiveValue::Set(id),
                user_id: ActiveValue::Set(user_id),
                provider: ActiveValue::Set(provider.to_string()),
                provider_user_id: ActiveValue::Set(provider_user_id.to_string()),
                ..Default::default()
            };
            UserConnections::insert(new_conn).exec(db).await?;
        }

        Ok(())
    }
}

#[async_trait]
impl AuthRepository for AuthORM {
    async fn find_user_by_id(&self, id: i64) -> Result<Option<User>, AppError> {
        let user = Users::find()
            .filter(users::Column::Id.eq(id))
            .filter(users::Column::DeletedAt.is_null())
            .one(&self.db)
            .await?;

        Ok(user.map(|u| self.to_user(u)))
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        let user = Users::find()
            .filter(users::Column::Email.eq(email))
            .filter(users::Column::DeletedAt.is_null())
            .one(&self.db)
            .await?;

        Ok(user.map(|u| self.to_user(u)))
    }

    async fn find_all_users(&self, page: u64, per_page: u64) -> Result<(Vec<User>, u64), AppError> {
        let query = Users::find()
            .filter(users::Column::DeletedAt.is_null())
            .order_by_desc(users::Column::CreatedAt);

        let paginator = query.paginate(&self.db, per_page);
        let total_items = paginator.num_items().await?;
        let models = paginator.fetch_page(page).await?;
        let users = models.into_iter().map(|m| self.to_user(m)).collect();

        Ok((users, total_items))
    }

    async fn update_user(&self, payload: UserUpdatePayload) -> Result<(), AppError> {
        let mut active_model = users::ActiveModel { ..Default::default() };

        if let Some(full_name) = payload.full_name {
            active_model.full_name = ActiveValue::Set(full_name);
        }
        if let Some(avatar_url) = payload.avatar_url {
            active_model.avatar_url = ActiveValue::Set(Some(avatar_url));
        }
        if let Some(email) = payload.email {
            active_model.email = ActiveValue::Set(email);
        }
        if let Some(status) = payload.status {
            active_model.status = ActiveValue::Set(status as i16);
        }

        if active_model.is_changed() {
            let result = Users::update_many()
                .set(active_model)
                .filter(users::Column::Id.eq(payload.id))
                .exec(&self.db)
                .await?;

            // If no rows were affected, it means the user ID was not found.
            if result.rows_affected == 0 {
                return Err(AppError::NotFound("User not found".to_string()));
            }
        }

        Ok(())
    }

    async fn find_user_credential_by_user_id(&self, uid: i64) -> Result<Option<UserCredential>, AppError> {
        let model = UserCredentials::find()
            .filter(user_credentials::Column::UserId.eq(uid))
            .one(&self.db)
            .await?;

        Ok(model.map(|m| self.to_user_credential(m)))
    }

    async fn create_user_with_credential(&self, user: User, password: String) -> Result<(), AppError> {
        let txn = self.db.begin().await?;

        let user_model = users::ActiveModel {
            id: ActiveValue::Set(user.id),
            email: ActiveValue::Set(user.email),
            full_name: ActiveValue::Set(user.full_name),
            status: ActiveValue::Set(user.status as i16),
            ..Default::default()
        };

        let cred_model = user_credentials::ActiveModel {
            user_id: ActiveValue::Set(user.id),
            hashed_password: ActiveValue::Set(password),
            ..Default::default()
        };

        Users::insert(user_model).exec(&txn).await?;
        UserCredentials::insert(cred_model).exec(&txn).await?;

        Ok(txn.commit().await?)
    }

    async fn update_user_credential(&self, user_id: i64, new_password: &str) -> Result<(), AppError> {
        UserCredentials::update_many()
            .col_expr(
                user_credentials::Column::HashedPassword,
                Expr::value(new_password.to_owned()),
            )
            .filter(user_credentials::Column::UserId.eq(user_id))
            .exec(&self.db)
            .await?;

        Ok(())
    }

    async fn find_user_connections_by_user_id(&self, user_id: i64) -> Result<Vec<UserConnection>, AppError> {
        let connections = UserConnections::find()
            .filter(user_connections::Column::UserId.eq(user_id))
            .all(&self.db)
            .await?;

        let output = connections
            .into_iter()
            .map(|model| self.to_user_connection(model))
            .collect();

        Ok(output)
    }

    async fn find_or_create_oauth_user(&self, payload: OAuthUserProfile) -> Result<User, AppError> {
        if let Some(user_model) = Users::find()
            .filter(users::Column::Email.eq(&payload.email))
            .one(&self.db)
            .await?
        {
            self.ensure_user_connection(
                &self.db,
                self.uid.generate()?,
                user_model.id,
                &payload.provider,
                &payload.provider_user_id,
            )
            .await?;

            return Ok(self.to_user(user_model));
        }

        let txn = self.db.begin().await?;
        let new_user_id = self.uid.generate()?;

        let new_user = users::ActiveModel {
            id: ActiveValue::Set(new_user_id),
            email: ActiveValue::Set(payload.email),
            full_name: ActiveValue::Set(payload.name),
            avatar_url: ActiveValue::Set(payload.avatar_url),
            status: ActiveValue::Set(UserStatus::Active as i16),
            ..Default::default()
        };

        let user_model = Users::insert(new_user).exec_with_returning(&txn).await?;

        self.ensure_user_connection(
            &txn,
            self.uid.generate()?,
            new_user_id,
            &payload.provider,
            &payload.provider_user_id,
        )
        .await?;

        txn.commit().await?;

        Ok(self.to_user(user_model))
    }

    async fn delete_oauth_user(&self, user_id: i64, connection_id: i64) -> Result<(), AppError> {
        let result = UserConnections::delete_many()
            .filter(user_connections::Column::Id.eq(connection_id))
            .filter(user_connections::Column::UserId.eq(user_id))
            .exec(&self.db)
            .await?;

        if result.rows_affected == 0 {
            return Err(AppError::NotFound("Connection not found".to_string()));
        }

        Ok(())
    }

    async fn find_mfa_factors_by_user_id(&self, user_id: i64) -> Result<Vec<MfaFactor>, AppError> {
        let models = MfaFactors::find()
            .filter(mfa_factors::Column::UserId.eq(user_id))
            .all(&self.db)
            .await?;

        let factors = models.into_iter().map(|m| self.to_mfa_factor(m)).collect();

        Ok(factors)
    }

    async fn find_unverified_mfa_factor_by_id_and_user_id(
        &self,
        user_id: i64,
        factor_id: i64,
    ) -> Result<Option<MfaFactor>, AppError> {
        let factor = MfaFactors::find()
            .filter(mfa_factors::Column::Id.eq(factor_id))
            .filter(mfa_factors::Column::UserId.eq(user_id))
            .filter(mfa_factors::Column::IsVerified.eq(false))
            .one(&self.db)
            .await?;

        Ok(factor.map(|m| self.to_mfa_factor(m)))
    }

    async fn create_mfa_factor(&self, factor: MfaFactor) -> Result<(), AppError> {
        let factor_model = mfa_factors::ActiveModel {
            id: ActiveValue::Set(factor.id),
            user_id: ActiveValue::Set(factor.user_id),
            r#type: ActiveValue::Set(factor.mfa_type as i16),
            secret: ActiveValue::Set(factor.secret),
            friendly_name: ActiveValue::Set(factor.friendly_name),
            ..Default::default()
        };

        MfaFactors::insert(factor_model).exec(&self.db).await?;

        Ok(())
    }

    async fn verify_mfa_factor(&self, factor_id: i64) -> Result<(), AppError> {
        MfaFactors::update_many()
            .col_expr(mfa_factors::Column::IsVerified, Expr::value(true))
            .filter(mfa_factors::Column::Id.eq(factor_id))
            .exec(&self.db)
            .await?;

        Ok(())
    }

    async fn delete_mfa_factor_by_id(&self, user_id: i64, factor_id: i64) -> Result<(), AppError> {
        let result = MfaFactors::delete_many()
            .filter(mfa_factors::Column::Id.eq(factor_id))
            .filter(mfa_factors::Column::UserId.eq(user_id))
            .exec(&self.db)
            .await?;

        if result.rows_affected == 0 {
            return Err(AppError::NotFound("Factor not found".to_string()));
        }

        Ok(())
    }

    async fn roles_exist(&self, role_ids: &[i64]) -> Result<bool, AppError> {
        if role_ids.is_empty() {
            return Ok(true); // An empty set of roles is vacuously valid.
        }

        let count = Roles::find()
            .filter(roles::Column::Id.is_in(role_ids.to_vec()))
            .count(&self.db)
            .await?;

        Ok(count == role_ids.len() as u64)
    }

    async fn set_user_roles(&self, user_id: i64, role_ids: Vec<i64>) -> Result<(), AppError> {
        let txn = self.db.begin().await?;

        UserRoles::delete_many()
            .filter(user_roles::Column::UserId.eq(user_id))
            .exec(&txn)
            .await?;

        if !role_ids.is_empty() {
            let new_roles = role_ids.into_iter().map(|role_id| user_roles::ActiveModel {
                user_id: ActiveValue::Set(user_id),
                role_id: ActiveValue::Set(role_id),
            });
            UserRoles::insert_many(new_roles).exec(&txn).await?;
        }

        Ok(txn.commit().await?)
    }
}
