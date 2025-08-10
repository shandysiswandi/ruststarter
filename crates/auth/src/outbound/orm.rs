use std::sync::Arc;

use app_core::error::AppError;
use app_core::time::utc_to_fixed_offset;
use app_core::uid::Generator;
use app_orm::prelude::{MfaFactors, Roles, UserConnections, UserCredentials, UserRoles, UserVerifications, Users};
use app_orm::{mfa_factors, roles, user_connections, user_credentials, user_roles, user_verifications, users};
use async_trait::async_trait;
use sea_orm::prelude::Expr;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, TransactionTrait,
};

use super::repository::AuthRepository;
use crate::domain::entity::mfa::{MfaFactor, MfaFactorType};
use crate::domain::entity::oauth::OAuthUserProfile;
use crate::domain::entity::user::{NewUser, User, UserStatus, UserUpdatePayload};
use crate::domain::entity::user_connection::UserConnection;
use crate::domain::entity::user_credential::UserCredential;
use crate::domain::entity::user_verifcation::UserVerification;

/// `AuthORM` is the data access layer for authentication-related entities.
///
/// It provides mapping functions between database models and domain entities,
/// as well as helper methods to ensure relationships like user connections
/// exist in the database.
///
/// # Responsibilities
/// - Hold the database connection for executing queries.
/// - Hold a UID generator for creating unique IDs.
/// - Convert SeaORM `Model` structs into domain-level entities used by the auth
///   module.
/// - Provide helper functions for creating or ensuring the existence of
///   auth-related data.
pub struct AuthORM {
    /// Database connection handle used for queries.
    db: Arc<DatabaseConnection>,
    /// Unique ID generator used for creating new entity IDs.
    uid: Arc<dyn Generator>,
}

impl AuthORM {
    /// Creates a new `AuthORM` with the given database connection and UID
    /// generator.
    pub fn new(db: Arc<DatabaseConnection>, uid: Arc<dyn Generator>) -> Self {
        Self { db, uid }
    }

    // ===== Mappers from database models to domain entities =====

    /// Converts a `users::Model` into a `User` domain entity.
    fn to_user(&self, model: users::Model) -> User {
        User {
            id: model.id,
            email: model.email,
            full_name: model.full_name,
            avatar_url: model.avatar_url,
            status: UserStatus::from_i16(model.status),
            created_at: model.created_at.into(),
            updated_at: model.updated_at.into(),
        }
    }

    /// Converts a `user_credentials::Model` into a `UserCredential` domain
    /// entity.
    fn to_user_credential(&self, model: user_credentials::Model) -> UserCredential {
        UserCredential { password: model.hashed_password }
    }

    /// Converts a `user_verifications::Model` into a `UserVerification` domain
    /// entity.
    fn to_user_verification(&self, model: user_verifications::Model) -> UserVerification {
        UserVerification { user_id: model.user_id, token: model.token, expires_at: model.expires_at.into() }
    }

    /// Converts a `user_connections::Model` into a `UserConnection` domain
    /// entity.
    fn to_user_connection(&self, model: user_connections::Model) -> UserConnection {
        UserConnection {
            id: model.id,
            user_id: model.user_id,
            provider: model.provider,
            provider_user_id: model.provider_user_id,
            created_at: model.created_at.into(),
        }
    }

    /// Converts a `mfa_factors::Model` into a `MfaFactor` domain entity.
    fn to_mfa_factor(&self, model: mfa_factors::Model) -> MfaFactor {
        MfaFactor {
            id: model.id,
            user_id: model.user_id,
            mfa_type: MfaFactorType::from_i16(model.r#type),
            friendly_name: model.friendly_name,
            secret: model.secret,
            is_verified: model.is_verified,
        }
    }

    // ===== Helpers =====

    /// Ensures a user connection exists in the database for the given `user_id`
    /// and `provider`.
    ///
    /// If no connection exists for the provider, it inserts a new one with the
    /// given details.
    ///
    /// # Arguments
    /// - `db`: A connection or transaction implementing `ConnectionTrait`.
    /// - `id`: The new ID to assign to the connection if it needs to be
    ///   created.
    /// - `user_id`: The ID of the user who owns the connection.
    /// - `provider`: The OAuth or identity provider name (e.g., `"google"`,
    ///   `"github"`).
    /// - `provider_user_id`: The provider-specific user ID.
    ///
    /// # Errors
    /// Returns `AppError` if the database query or insert operation fails.
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
            .one(self.db.as_ref())
            .await?;

        Ok(user.map(|u| self.to_user(u)))
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        let user = Users::find()
            .filter(users::Column::Email.eq(email))
            .filter(users::Column::DeletedAt.is_null())
            .one(self.db.as_ref())
            .await?;

        Ok(user.map(|u| self.to_user(u)))
    }

    async fn find_all_users(&self, page: u64, per_page: u64) -> Result<(Vec<User>, u64), AppError> {
        let query = Users::find()
            .filter(users::Column::DeletedAt.is_null())
            .order_by_desc(users::Column::CreatedAt);

        let paginator = query.paginate(self.db.as_ref(), per_page);
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
                .exec(self.db.as_ref())
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
            .one(self.db.as_ref())
            .await?;

        Ok(model.map(|m| self.to_user_credential(m)))
    }

    async fn create_new_user(&self, new_user: &NewUser) -> Result<(), AppError> {
        let txn = self.db.begin().await?;

        let user_model = users::ActiveModel {
            id: ActiveValue::Set(new_user.id),
            email: ActiveValue::Set(new_user.email.clone()),
            full_name: ActiveValue::Set(new_user.full_name.clone()),
            status: ActiveValue::Set(new_user.status.clone() as i16),
            ..Default::default()
        };

        let cred_model = user_credentials::ActiveModel {
            user_id: ActiveValue::Set(new_user.id),
            hashed_password: ActiveValue::Set(new_user.password.clone()),
            ..Default::default()
        };

        let verify_model = user_verifications::ActiveModel {
            user_id: ActiveValue::Set(new_user.id),
            token: ActiveValue::Set(new_user.verify_token.clone()),
            expires_at: ActiveValue::Set(utc_to_fixed_offset(&new_user.verify_expiry)),
            ..Default::default()
        };

        Users::insert(user_model).exec(&txn).await?;
        UserCredentials::insert(cred_model).exec(&txn).await?;
        UserVerifications::insert(verify_model).exec(&txn).await?;

        Ok(txn.commit().await?)
    }

    async fn update_user_credential(&self, user_id: i64, new_password: &str) -> Result<(), AppError> {
        UserCredentials::update_many()
            .col_expr(user_credentials::Column::HashedPassword, Expr::value(new_password.to_owned()))
            .filter(user_credentials::Column::UserId.eq(user_id))
            .exec(self.db.as_ref())
            .await?;

        Ok(())
    }

    async fn find_user_verification_by_token(&self, token: &str) -> Result<Option<UserVerification>, AppError> {
        let user_verify = UserVerifications::find()
            .filter(user_verifications::Column::Token.eq(token))
            .one(self.db.as_ref())
            .await?;

        Ok(user_verify.map(|m| self.to_user_verification(m)))
    }

    async fn verify_user_and_delete_token(&self, user_id: i64, token: &str) -> Result<(), AppError> {
        let txn = self.db.begin().await?;

        let res_user = Users::update_many()
            .col_expr(users::Column::Status, Expr::value(UserStatus::Active as i64))
            .filter(users::Column::Id.eq(user_id))
            .exec(&txn)
            .await?;

        if res_user.rows_affected == 0 {
            txn.rollback().await?;
            return Err(AppError::NotFound("User not found".into()));
        }

        let res_verify = UserVerifications::delete_many()
            .filter(user_verifications::Column::Token.eq(token))
            .filter(user_verifications::Column::UserId.eq(user_id))
            .exec(self.db.as_ref())
            .await?;

        if res_verify.rows_affected == 0 {
            txn.rollback().await?;
            return Err(AppError::NotFound("No user verification found".into()));
        }

        Ok(txn.commit().await?)
    }

    async fn find_user_connections_by_user_id(&self, user_id: i64) -> Result<Vec<UserConnection>, AppError> {
        let connections = UserConnections::find()
            .filter(user_connections::Column::UserId.eq(user_id))
            .all(self.db.as_ref())
            .await?;

        Ok(connections.into_iter().map(|model| self.to_user_connection(model)).collect())
    }

    async fn find_or_create_oauth_user(&self, payload: OAuthUserProfile) -> Result<User, AppError> {
        if let Some(user_model) = Users::find()
            .filter(users::Column::Email.eq(&payload.email))
            .one(self.db.as_ref())
            .await?
        {
            self.ensure_user_connection(
                self.db.as_ref(),
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
            .exec(self.db.as_ref())
            .await?;

        if result.rows_affected == 0 {
            return Err(AppError::NotFound("Connection not found".to_string()));
        }

        Ok(())
    }

    async fn find_mfa_factors_by_user_id(&self, user_id: i64) -> Result<Vec<MfaFactor>, AppError> {
        let models = MfaFactors::find()
            .filter(mfa_factors::Column::UserId.eq(user_id))
            .all(self.db.as_ref())
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
            .one(self.db.as_ref())
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

        MfaFactors::insert(factor_model).exec(self.db.as_ref()).await?;

        Ok(())
    }

    async fn verify_mfa_factor(&self, factor_id: i64) -> Result<(), AppError> {
        MfaFactors::update_many()
            .col_expr(mfa_factors::Column::IsVerified, Expr::value(true))
            .filter(mfa_factors::Column::Id.eq(factor_id))
            .exec(self.db.as_ref())
            .await?;

        Ok(())
    }

    async fn delete_mfa_factor_by_id(&self, user_id: i64, factor_id: i64) -> Result<(), AppError> {
        let result = MfaFactors::delete_many()
            .filter(mfa_factors::Column::Id.eq(factor_id))
            .filter(mfa_factors::Column::UserId.eq(user_id))
            .exec(self.db.as_ref())
            .await?;

        if result.rows_affected == 0 {
            return Err(AppError::NotFound("Factor not found".to_string()));
        }

        Ok(())
    }

    async fn roles_exist(&self, role_ids: &[i64]) -> Result<bool, AppError> {
        if role_ids.is_empty() {
            return Ok(false); // An empty set of roles is vacuously valid.
        }

        let count = Roles::find()
            .filter(roles::Column::Id.is_in(role_ids.to_vec()))
            .count(self.db.as_ref())
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use app_core::uid::MockGenerator;
    use chrono::{FixedOffset, Utc};
    use sea_orm::{DatabaseBackend, DbErr, MockDatabase, MockExecResult, ModelTrait, Value};

    use super::*;

    async fn setup_mock_db<T>(
        query_results: Option<Vec<Vec<T>>>,
        exec_results: Option<Vec<MockExecResult>>,
        query_errors: Option<Vec<sea_orm::DbErr>>,
        exec_errors: Option<Vec<sea_orm::DbErr>>,
        pagination_count: Option<u64>,
    ) -> AuthORM
    where
        T: ModelTrait + Clone + Send + Sync + 'static,
    {
        let mut db = MockDatabase::new(DatabaseBackend::Postgres);

        if let Some(qr) = query_results {
            if let Some(count) = pagination_count {
                db = db
                    .append_query_results(vec![vec![BTreeMap::from([(
                        "num_items".to_string(),
                        Value::BigUnsigned(Some(count)),
                    )])]])
                    .append_query_results(qr);
            } else {
                db = db.append_query_results(qr);
            }
        }

        if let Some(er) = exec_results {
            db = db.append_exec_results(er);
        }

        if let Some(qe) = query_errors {
            db = db.append_query_errors(qe);
        }

        if let Some(ee) = exec_errors {
            db = db.append_exec_errors(ee);
        }

        AuthORM::new(Arc::new(db.into_connection()), Arc::new(MockGenerator::new()))
    }

    #[tokio::test]
    async fn test_find_user_by_id() {
        let now = Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap());
        let test_user = users::Model {
            id: 1,
            email: "test@example.com".to_string(),
            full_name: "Test User".to_string(),
            avatar_url: None,
            status: 1,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let repo = setup_mock_db(
            Some(vec![vec![test_user.clone()], vec![]]), // query_results
            None,                                        // exec_results
            None,                                        // query_errors
            None,                                        // exec_errors
            None,                                        // pagination_count
        )
        .await;

        let user = repo.find_user_by_id(1).await.unwrap().unwrap();

        assert_eq!(user.id, 1);
        assert_eq!(user.full_name, "Test User");

        let user_not_found = repo.find_user_by_id(2).await.unwrap();
        assert!(user_not_found.is_none());
    }

    #[tokio::test]
    async fn test_find_user_by_email() {
        let now = Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap());
        let test_user = users::Model {
            id: 1,
            email: "test@example.com".to_string(),
            full_name: "Test User".to_string(),
            avatar_url: None,
            status: 1,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let repo = setup_mock_db(
            Some(vec![vec![test_user.clone()], vec![]]), // query_results
            None,                                        // exec_results
            None,                                        // query_errors
            None,                                        // exec_errors
            None,                                        // pagination_count
        )
        .await;

        let user = repo.find_user_by_email("test@example.com").await.unwrap().unwrap();

        assert_eq!(user.id, 1);
        assert_eq!(user.full_name, "Test User");

        let user_not_found = repo.find_user_by_email("user_not_found@example.com").await.unwrap();
        assert!(user_not_found.is_none());
    }

    #[tokio::test]
    #[ignore = "not yet finished"]
    async fn test_find_all_users() {
        let now = Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap());

        let user = users::Model {
            id: 1,
            email: "alice@example.com".to_string(),
            full_name: "Alice".to_string(),
            avatar_url: None,
            status: 1,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let repo = setup_mock_db(
            Some(vec![
                vec![user.clone(), user.clone()], // First query result for count
                vec![user.clone(), user.clone()], // Second query result for page data
            ]),
            None,
            None,
            None,
            Some(2), // pagination_count
        )
        .await;

        // Call the function
        let (users, total) = repo.find_all_users(0, 10).await.unwrap();

        // Validate count and user mapping
        assert_eq!(total, 2); // num_items
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].id, 1);
        assert_eq!(users[0].full_name, "Alice");
    }

    #[tokio::test]
    async fn test_update_user() {
        // case 1
        let repo = setup_mock_db::<users::Model>(None, None, None, None, None).await;
        let payload = UserUpdatePayload { id: 1, full_name: None, avatar_url: None, email: None, status: None };
        let result = repo.update_user(payload).await;
        assert!(result.is_ok(), "Expected Ok when no fields are updated");

        // case 2
        let exec_result_success = sea_orm::MockExecResult { last_insert_id: 0, rows_affected: 1 };
        let repo = setup_mock_db::<users::Model>(None, Some(vec![exec_result_success]), None, None, None).await;
        let payload = UserUpdatePayload {
            id: 1,
            full_name: Some("Updated User".to_string()),
            avatar_url: Some("http://example.com/avatar.png".to_string()),
            email: Some("updated@example.com".to_string()),
            status: Some(UserStatus::Active),
        };
        let result = repo.update_user(payload).await;
        assert!(result.is_ok(), "Expected Ok when update succeeds");

        // case 3
        let exec_result_not_found = sea_orm::MockExecResult { last_insert_id: 0, rows_affected: 0 };
        let repo = setup_mock_db::<users::Model>(None, Some(vec![exec_result_not_found]), None, None, None).await;
        let payload = UserUpdatePayload {
            id: 999,
            full_name: Some("Ghost".to_string()),
            avatar_url: None,
            email: None,
            status: None,
        };
        let result = repo.update_user(payload).await;
        assert!(result.is_err(), "Expected error when user not found");
        match result.unwrap_err() {
            AppError::NotFound(msg) => assert_eq!(msg, "User not found"),
            e => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_find_user_credential_by_user_id() {
        // case 1
        let cred_model = user_credentials::Model {
            user_id: 1,
            hashed_password: "hashed_pw".to_string(),
            password_last_changed_at: Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap()),
        };
        let repo = setup_mock_db(
            Some(vec![vec![cred_model], vec![]]), // query returns one row
            None,
            None,
            None,
            None,
        )
        .await;

        let cred = repo.find_user_credential_by_user_id(1).await.unwrap();
        assert!(cred.is_some(), "Expected Some(UserCredential)");
        assert_eq!(cred.unwrap().password, "hashed_pw");

        // case 2
        let cred = repo.find_user_credential_by_user_id(2).await.unwrap();
        assert!(cred.is_none(), "Expected None when no credential found");
    }

    #[tokio::test]
    async fn test_create_user_with_credential() {
        // let new_user = NewUser {
        //     id: 1,
        //     email: "test@example.com".to_string(),
        //     full_name: "Test User".to_string(),
        //     status: UserStatus::Active,
        // };
        let new_user = NewUser {
            id: 1,
            email: "test@example.com".to_string(),
            full_name: "Test User".to_string(),
            status: UserStatus::Active,
            password: "hashed pw".into(),
            verify_token: "token".into(),
            verify_expiry: Utc::now(),
        };

        // case 1
        let exec_results = vec![
            MockExecResult { last_insert_id: 1, rows_affected: 1 }, // insert user
            MockExecResult { last_insert_id: 1, rows_affected: 1 }, // insert credential
            MockExecResult { last_insert_id: 0, rows_affected: 0 }, // commit txn
        ];
        let repo = setup_mock_db::<users::Model>(None, Some(exec_results), None, None, None).await;
        let result = repo.create_new_user(&new_user).await;
        assert!(result.is_ok(), "Expected Ok on successful insert + commit");

        // case 2
        let repo = setup_mock_db::<users::Model>(
            None,
            None,
            None,
            Some(vec![DbErr::Exec(sea_orm::RuntimeErr::Internal("sql error".into()))]),
            None,
        )
        .await;
        let result = repo.create_new_user(&new_user).await;
        assert!(result.is_err(), "Expected error when insert fails");
    }

    #[tokio::test]
    async fn test_update_user_credential() {
        // case 1
        let repo = setup_mock_db::<user_credentials::Model>(
            None,
            Some(vec![MockExecResult { last_insert_id: 0, rows_affected: 1 }]),
            None,
            None,
            None,
        )
        .await;
        let result = repo.update_user_credential(1, "new_hashed_pw").await;
        assert!(result.is_ok(), "Expected Ok when update succeeds");

        // case 2
        let repo = setup_mock_db::<user_credentials::Model>(
            None,
            None,
            None,
            Some(vec![sea_orm::DbErr::Exec(sea_orm::RuntimeErr::Internal("sql error".into()))]),
            None,
        )
        .await;
        let result = repo.update_user_credential(1, "new_hashed_pw").await;
        assert!(result.is_err(), "Expected Err when DB update fails");
    }

    #[tokio::test]
    async fn test_find_user_connections_by_user_id() {
        let now = Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap());

        // case 1
        let model = user_connections::Model {
            id: 1,
            user_id: 1,
            provider: "github".to_string(),
            provider_user_id: "gh_123".to_string(),
            created_at: now,
        };
        let repo = setup_mock_db(
            Some(vec![vec![model.clone(), model.clone()], vec![]]), // query returns 2 rows
            None,
            None,
            None,
            None,
        )
        .await;
        let conns = repo.find_user_connections_by_user_id(1).await.unwrap();
        assert_eq!(conns.len(), 2, "Expected 2 connections");
        assert_eq!(conns[0].provider, "github");

        // case 2
        let conns = repo.find_user_connections_by_user_id(2).await.unwrap();
        assert!(conns.is_empty(), "Expected empty vec when no connections found");
    }

    #[tokio::test]
    #[ignore = "not yet finished"]
    async fn test_find_or_create_oauth_user() {}

    #[tokio::test]
    async fn test_delete_oauth_user() {
        // case 1
        let repo = setup_mock_db::<user_connections::Model>(
            None,
            Some(vec![
                MockExecResult { last_insert_id: 0, rows_affected: 1 },
                MockExecResult { last_insert_id: 0, rows_affected: 0 },
            ]),
            None,
            None,
            None,
        )
        .await;
        let result = repo.delete_oauth_user(1, 10).await;
        assert!(result.is_ok(), "Expected Ok when connection is deleted");

        // case 2
        let result = repo.delete_oauth_user(1, 99).await;
        assert!(
            matches!(result, Err(AppError::NotFound(_))),
            "Expected NotFound error when no connection deleted"
        );
    }

    #[tokio::test]
    async fn test_find_mfa_factors_by_user_id() {
        let now = Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap());

        // case 1
        let model = mfa_factors::Model {
            id: 1,
            user_id: 1,
            r#type: 1,
            secret: "secret123".to_string(),
            created_at: now,
            updated_at: now,
            friendly_name: Some("friendly_name".into()),
            is_verified: true,
        };

        let repo = setup_mock_db(
            Some(vec![vec![model.clone(), model.clone()], vec![]]), // query result
            None,
            None,
            None,
            None,
        )
        .await;

        let factors = repo.find_mfa_factors_by_user_id(1).await.unwrap();
        assert_eq!(factors.len(), 2, "Expected 2 MFA factors");
        assert_eq!(factors[0].mfa_type, MfaFactorType::Totp);

        // case 2
        let factors = repo.find_mfa_factors_by_user_id(2).await.unwrap();
        assert!(factors.is_empty(), "Expected empty vec when user has no factors");
    }

    #[tokio::test]
    async fn test_find_unverified_mfa_factor_by_id_and_user_id() {
        let now = Utc::now().with_timezone(&FixedOffset::east_opt(0).unwrap());

        // case 1
        let model = mfa_factors::Model {
            id: 1,
            user_id: 1,
            r#type: 1,
            secret: "secret123".to_string(),
            created_at: now,
            updated_at: now,
            friendly_name: Some("friendly_name".into()),
            is_verified: false,
        };

        let repo = setup_mock_db(
            Some(vec![vec![model.clone()], vec![]]), // query returns 1 factor
            None,
            None,
            None,
            None,
        )
        .await;

        let factor = repo.find_unverified_mfa_factor_by_id_and_user_id(1, 1).await.unwrap();
        assert!(factor.is_some(), "Expected Some(MfaFactor)");
        assert_eq!(factor.unwrap().id, 1);

        // case 2
        let factor = repo.find_unverified_mfa_factor_by_id_and_user_id(1, 99).await.unwrap();
        assert!(factor.is_none(), "Expected None when no unverified factor found");
    }

    #[tokio::test]
    async fn test_create_mfa_factor() {
        let factor = MfaFactor {
            id: 1,
            user_id: 1,
            mfa_type: MfaFactorType::Totp,
            friendly_name: Some("name".into()),
            secret: "secret".into(),
            is_verified: false,
        };

        // case 1
        let repo = setup_mock_db::<mfa_factors::Model>(
            None,
            Some(vec![MockExecResult { last_insert_id: 1, rows_affected: 1 }]),
            None,
            None,
            None,
        )
        .await;

        let result = repo.create_mfa_factor(factor.clone()).await;
        assert!(result.is_ok(), "Expected Ok when insert succeeds");

        // case 2
        let repo = setup_mock_db::<mfa_factors::Model>(
            None,
            None,
            None,
            Some(vec![sea_orm::DbErr::Exec(sea_orm::RuntimeErr::Internal("sql error".into()))]),
            None,
        )
        .await;

        let result = repo.create_mfa_factor(factor).await;
        assert!(result.is_err(), "Expected Err when DB insert fails");
    }

    #[tokio::test]
    async fn test_verify_mfa_factor() {
        // case 1
        let repo = setup_mock_db::<mfa_factors::Model>(
            None,
            Some(vec![
                MockExecResult { last_insert_id: 0, rows_affected: 1 },
                MockExecResult { last_insert_id: 0, rows_affected: 0 },
            ]),
            None,
            None,
            None,
        )
        .await;
        let result = repo.verify_mfa_factor(1).await;
        assert!(result.is_ok(), "Expected Ok when update succeeds");

        // case 2
        let result = repo.verify_mfa_factor(99).await;
        assert!(result.is_ok(), "Expected Ok even if no factor was updated (rows_affected = 0)");

        // case 3
        let repo = setup_mock_db::<mfa_factors::Model>(
            None,
            None,
            None,
            Some(vec![sea_orm::DbErr::Exec(sea_orm::RuntimeErr::Internal("sql error".into()))]),
            None,
        )
        .await;
        let result = repo.verify_mfa_factor(1).await;
        assert!(result.is_err(), "Expected Err when DB update fails");
    }

    #[tokio::test]
    async fn test_delete_mfa_factor_by_id() {
        // case 1
        let repo = setup_mock_db::<mfa_factors::Model>(
            None,
            Some(vec![
                MockExecResult { last_insert_id: 0, rows_affected: 1 },
                MockExecResult { last_insert_id: 0, rows_affected: 0 },
            ]),
            None,
            None,
            None,
        )
        .await;

        let result = repo.delete_mfa_factor_by_id(1, 1).await;
        assert!(result.is_ok(), "Expected Ok when factor is deleted");

        // case 2
        let result = repo.delete_mfa_factor_by_id(1, 99).await;
        assert!(
            matches!(result, Err(AppError::NotFound(_))),
            "Expected NotFound error when factor does not exist"
        );

        // case 3
        let repo = setup_mock_db::<mfa_factors::Model>(
            None,
            None,
            None,
            Some(vec![sea_orm::DbErr::Exec(sea_orm::RuntimeErr::Internal("sql error".into()))]),
            None,
        )
        .await;

        let result = repo.delete_mfa_factor_by_id(1, 1).await;
        assert!(result.is_err(), "Expected Err when DB delete fails");
    }

    #[tokio::test]
    #[ignore = "not yet finished"]
    async fn test_roles_exist() {
        // use sea_orm::MockQueryResult;

        // case 1
        let repo = setup_mock_db::<roles::Model>(None, None, None, None, None).await;
        let result = repo.roles_exist(&[]).await.unwrap();
        assert!(!result, "Expected false for empty role_ids");

        // case 2
        // let query_results = vec![MockQueryResult::new().set_count(2)]; // DB says 2
        // found let repo = setup_mock_db(Some(vec![query_results]), None, None,
        // None, None).await;

        // let result = repo.roles_exist(&[1, 2]).await.unwrap();
        // assert!(result, "Expected true when all role_ids exist");

        // // case 3
        // let query_results = vec![MockQueryResult::new().set_count(1)]; // DB says
        // only 1 found let repo = setup_mock_db(Some(vec![query_results]),
        // None, None, None, None).await; let result = repo.roles_exist(&[1,
        // 2]).await.unwrap(); assert!(!result, "Expected false when some
        // role_ids are missing");

        // case 4
        let repo = setup_mock_db::<roles::Model>(
            None,
            None,
            None,
            Some(vec![sea_orm::DbErr::Query(sea_orm::RuntimeErr::Internal("sql error".into()))]),
            None,
        )
        .await;
        let result = repo.roles_exist(&[1]).await;
        assert!(result.is_err(), "Expected Err when DB query fails");
    }

    #[tokio::test]
    async fn test_set_user_roles() {
        // case 1
        let repo = setup_mock_db::<user_roles::Model>(
            None,
            Some(vec![
                MockExecResult { last_insert_id: 0, rows_affected: 1 }, // delete_many
                MockExecResult { last_insert_id: 0, rows_affected: 2 }, // insert_many
                MockExecResult { last_insert_id: 0, rows_affected: 1 }, // commit
            ]),
            None,
            None,
            None,
        )
        .await;
        let result = repo.set_user_roles(1, vec![1, 2]).await;
        assert!(result.is_ok(), "Expected Ok when setting roles succeeds");

        // case 2
        let repo = setup_mock_db::<user_roles::Model>(
            None,
            Some(vec![
                MockExecResult { last_insert_id: 0, rows_affected: 1 }, // delete_many
                MockExecResult { last_insert_id: 0, rows_affected: 1 }, // commit
            ]),
            None,
            None,
            None,
        )
        .await;
        let result = repo.set_user_roles(1, vec![]).await;
        assert!(result.is_ok(), "Expected Ok when clearing roles");

        // case 3
        let repo = setup_mock_db::<user_roles::Model>(
            None,
            None,
            None,
            Some(vec![DbErr::Exec(sea_orm::RuntimeErr::Internal("delete fail".into()))]),
            None,
        )
        .await;
        let result = repo.set_user_roles(1, vec![1]).await;
        assert!(result.is_err(), "Expected Err when delete_many fails");

        // case 4
        let repo = setup_mock_db::<user_roles::Model>(
            None,
            None,
            None,
            Some(vec![DbErr::Exec(sea_orm::RuntimeErr::Internal("insert fail".into()))]),
            None,
        )
        .await;
        let result = repo.set_user_roles(1, vec![1, 2]).await;
        assert!(result.is_err(), "Expected Err when insert_many fails");

        // case 5
        let repo = setup_mock_db::<user_roles::Model>(
            None,
            None,
            None,
            Some(vec![DbErr::Exec(sea_orm::RuntimeErr::Internal("commit fail".into()))]),
            None,
        )
        .await;
        let result = repo.set_user_roles(1, vec![1]).await;
        assert!(result.is_err(), "Expected Err when commit fails");
    }
}
