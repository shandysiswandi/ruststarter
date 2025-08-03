use std::sync::Arc;

use crate::app::error::AppError;
use crate::app::uid::Generator;
use crate::auth::domain::connection::Connection;
use crate::auth::domain::mfa::MfaFactor;
use crate::auth::domain::user::{OAuthUserProfile, User};
use crate::auth::outbound::model::{ConnectionModel, MfaFactorModel, UserCredentialModel, UserModel};
use async_trait::async_trait;
use sqlx::{PgPool, Postgres, QueryBuilder};

#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait AuthDataSource: Send + Sync {
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AppError>;
    async fn create_user(&self, user: User) -> Result<bool, AppError>;
    async fn find_user_by_id(&self, user_id: i64) -> Result<Option<User>, AppError>;
    async fn update_user(
        &self,
        user_id: i64,
        full_name: Option<String>,
        avatar_url: Option<String>,
    ) -> Result<(), AppError>;
    async fn update_password(&self, user_id: i64, new_hashed_password: &str) -> Result<(), AppError>;
    async fn find_all_users(&self, page: u64, per_page: u64) -> Result<(Vec<User>, i64), AppError>;
    //
    async fn find_or_create_oauth_user(&self, profile: OAuthUserProfile) -> Result<User, AppError>;
    async fn find_connections_by_user_id(&self, user_id: i64) -> Result<Vec<Connection>, AppError>;
    async fn delete_connection_by_id(&self, user_id: i64, connection_id: i64) -> Result<u64, AppError>;
    //
    async fn find_mfa_factors_by_user_id(&self, user_id: i64) -> Result<Vec<MfaFactor>, AppError>;
    async fn delete_mfa_factor_by_id(&self, user_id: i64, factor_id: i64) -> Result<u64, AppError>;
    async fn create_mfa_factor(
        &self,
        user_id: i64,
        secret: &str,
        friendly_name: &str,
    ) -> Result<i64, AppError>;
    async fn find_unverified_mfa_factor_by_id(
        &self,
        user_id: i64,
        factor_id: i64,
    ) -> Result<Option<MfaFactor>, AppError>;
    async fn verify_mfa_factor(&self, factor_id: i64) -> Result<(), AppError>;
}

pub struct AuthSQL {
    pool: PgPool,
    uid: Arc<dyn Generator>,
}

impl AuthSQL {
    pub fn new(pool: PgPool, uid: Arc<dyn Generator>) -> Self {
        Self { pool, uid }
    }
}

#[async_trait]
impl AuthDataSource for AuthSQL {
    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        let model = sqlx::query_as::<_, UserCredentialModel>(
            r#"
                SELECT
                    u.id,
                    u.email,
                    u.full_name,
                    u.status,
                    uc.hashed_password as "password"
                FROM
                    users u
                JOIN
                    user_credentials uc ON u.id = uc.user_id
                WHERE
                    u.email = $1 AND u.deleted_at IS NULL
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(model.map(User::from))
    }

    async fn create_user(&self, user: User) -> Result<bool, AppError> {
        let mut tx = self.pool.begin().await?;

        sqlx::query("INSERT INTO users (id, full_name, email) VALUES ($1, $2, $3)")
            .bind(user.id)
            .bind(user.full_name)
            .bind(user.email)
            .execute(&mut *tx)
            .await?;

        sqlx::query("INSERT INTO user_credentials (user_id, hashed_password) VALUES ($1, $2)")
            .bind(user.id)
            .bind(user.password)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(true)
    }

    async fn find_mfa_factors_by_user_id(&self, user_id: i64) -> Result<Vec<MfaFactor>, AppError> {
        let models = sqlx::query_as::<_, MfaFactorModel>(
            r#"
                SELECT id, type, friendly_name, secret 
                FROM mfa_factors 
                WHERE user_id = $1 AND is_verified = TRUE
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(models.into_iter().map(Into::into).collect())
    }

    async fn delete_mfa_factor_by_id(&self, user_id: i64, factor_id: i64) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM mfa_factors WHERE id = $1 AND user_id = $2")
            .bind(factor_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    async fn find_user_by_id(&self, user_id: i64) -> Result<Option<User>, AppError> {
        let model = sqlx::query_as::<_, UserModel>(
            "SELECT id, email, full_name, status FROM users WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(model.map(User::from))
    }

    async fn find_or_create_oauth_user(&self, data: OAuthUserProfile) -> Result<User, AppError> {
        if let Some(user) = self.find_user_by_email(&data.email).await? {
            // TODO: Here you might link the OAuth provider to the existing account
            // in the `user_connections` table.
            return Ok(user);
        }

        // If not, create a new user.
        let new_user_id = self.uid.generate()?;
        let new_user = sqlx::query_as::<_, UserModel>(
            r#"
                INSERT INTO users (id, email, full_name, avatar_url, status)
                VALUES ($1, $2, $3, $4, 1) -- Set status to Active
                RETURNING id, email, full_name, status
            "#,
        )
        .bind(new_user_id)
        .bind(data.email)
        .bind(data.name)
        .bind(data.avatar_url)
        .fetch_one(&self.pool)
        .await?;

        Ok(User::from(new_user))
    }

    async fn update_user(
        &self,
        user_id: i64,
        full_name: Option<String>,
        avatar_url: Option<String>,
    ) -> Result<(), AppError> {
        if full_name.is_none() && avatar_url.is_none() {
            return Ok(()); // Nothing to update
        }

        let mut query_builder: QueryBuilder<Postgres> = QueryBuilder::new("UPDATE users SET ");
        let mut separated = query_builder.separated(", ");

        if let Some(name) = full_name {
            separated.push("full_name = ");
            separated.push_bind_unseparated(name);
        }

        if let Some(url) = avatar_url {
            separated.push("avatar_url = ");
            separated.push_bind_unseparated(url);
        }

        query_builder.push(" WHERE id = ");
        query_builder.push_bind(user_id);
        query_builder.build().execute(&self.pool).await?;

        Ok(())
    }

    async fn update_password(&self, user_id: i64, new_hashed_password: &str) -> Result<(), AppError> {
        sqlx::query("UPDATE user_credentials SET hashed_password = $1 WHERE user_id = $2")
            .bind(new_hashed_password)
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn find_all_users(&self, page: u64, per_page: u64) -> Result<(Vec<User>, i64), AppError> {
        let users = sqlx::query_as::<_, UserModel>(
            r#"
                SELECT id, email, full_name, avatar_url, status
                FROM users
                WHERE deleted_at IS NULL
                ORDER BY created_at DESC
                LIMIT $1 OFFSET $2
            "#,
        )
        .bind(per_page as i64)
        .bind(page as i64)
        .fetch_all(&self.pool)
        .await?;

        let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL")
            .fetch_one(&self.pool)
            .await?;

        Ok((users.into_iter().map(Into::into).collect(), total.0))
    }

    async fn find_connections_by_user_id(&self, user_id: i64) -> Result<Vec<Connection>, AppError> {
        let connections = sqlx::query_as::<_, ConnectionModel>(
            "SELECT id, provider, provider_user_id FROM user_connections WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(connections.into_iter().map(Into::into).collect())
    }

    async fn delete_connection_by_id(&self, user_id: i64, connection_id: i64) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM user_connections WHERE id = $1 AND user_id = $2")
            .bind(connection_id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }

    async fn create_mfa_factor(
        &self,
        user_id: i64,
        secret: &str,
        friendly_name: &str,
    ) -> Result<i64, AppError> {
        let id = self.uid.generate()?;

        sqlx::query(
            r#"
                INSERT INTO mfa_factors (id, user_id, type, secret, friendly_name)
                VALUES ($1, $2, 1, $3, $4) -- 1 = TOTP
            "#,
        )
        .bind(id)
        .bind(user_id)
        .bind(secret)
        .bind(friendly_name)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    async fn find_unverified_mfa_factor_by_id(
        &self,
        user_id: i64,
        factor_id: i64,
    ) -> Result<Option<MfaFactor>, AppError> {
        let model = sqlx::query_as::<_, MfaFactorModel>(
            r#"
                SELECT id, user_id, type, friendly_name, secret
                FROM mfa_factors
                WHERE id = $1 AND user_id = $2 AND is_verified = FALSE
            "#,
        )
        .bind(factor_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(model.map(Into::into))
    }

    async fn verify_mfa_factor(&self, factor_id: i64) -> Result<(), AppError> {
        sqlx::query("UPDATE mfa_factors SET is_verified = TRUE WHERE id = $1")
            .bind(factor_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
