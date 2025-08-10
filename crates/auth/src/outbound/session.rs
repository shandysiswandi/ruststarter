use app_core::error::AppError;
use async_trait::async_trait;
use bb8_redis::{RedisConnectionManager, bb8};
use redis::AsyncCommands;

/// Repository interface for managing session tokens.
///
/// Implementations of this trait are responsible for storing,
/// checking, and deleting session tokens (identified by `jti`).
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait SessionRepository: Send + Sync {
    /// Adds a session token with an expiration time.
    ///
    /// # Arguments
    ///
    /// * `jti` - The unique token identifier.
    /// * `exp_secs` - Expiration time in seconds.
    ///
    /// # Returns
    ///
    /// * `Ok(())` on success.
    /// * `Err(AppError)` if storing fails.
    async fn add_token(&self, jti: &str, exp_secs: u64) -> Result<(), AppError>;

    /// Checks if a session token exists.
    ///
    /// # Arguments
    ///
    /// * `jti` - The unique token identifier.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if the token exists.
    /// * `Ok(false)` if the token does not exist.
    /// * `Err(AppError)` if the check fails.
    async fn has_token(&self, jti: &str) -> Result<bool, AppError>;

    /// Deletes a session token.
    ///
    /// # Arguments
    ///
    /// * `jti` - The unique token identifier.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if deletion was successful or the token didn’t exist.
    /// * `Err(AppError)` if deletion fails.
    async fn delete_token(&self, jti: &str) -> Result<(), AppError>;
}

/// Redis-backed implementation of [`SessionRepository`].
///
/// Stores session tokens in Redis with a time-to-live (TTL) and
/// performs existence checks and deletions.
pub struct SessionRedis {
    pool: bb8::Pool<RedisConnectionManager>,
}

impl SessionRedis {
    /// Creates a new `SessionRedis` instance using the given Redis connection
    /// pool.
    pub fn new(pool: bb8::Pool<RedisConnectionManager>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for SessionRedis {
    async fn add_token(&self, jti: &str, exp_secs: u64) -> Result<(), AppError> {
        let mut conn = self.pool.get().await?;
        let _: () = conn.set_ex(format!("session:{jti}"), true, exp_secs).await?;
        Ok(())
    }

    async fn has_token(&self, jti: &str) -> Result<bool, AppError> {
        let mut conn = self.pool.get().await?;
        let exists: bool = conn.exists(format!("session:{jti}")).await?;
        Ok(exists)
    }

    async fn delete_token(&self, jti: &str) -> Result<(), AppError> {
        let mut conn = self.pool.get().await?;
        let _: () = conn.del(format!("session:{jti}")).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mockall::predicate::*;

    use super::*;

    #[tokio::test]
    async fn test_add_token_success() {
        let mut mock = MockSessionRepository::new();
        let jti = "test-jti-123";
        let exp_secs = 60;
        mock.expect_add_token()
            .with(eq(jti), eq(exp_secs))
            .times(1)
            .returning(|_, _| Box::pin(async move { Ok(()) }));

        assert!(mock.add_token(jti, exp_secs).await.is_ok());
    }

    #[tokio::test]
    async fn test_add_token_error() {
        let mut mock = MockSessionRepository::new();
        mock.expect_add_token()
            .returning(|_, _| Box::pin(async move { Err(AppError::Internal) }));

        assert!(mock.add_token("any", 10).await.is_err());
    }

    #[tokio::test]
    async fn test_has_token_true() {
        let mut mock = MockSessionRepository::new();
        let jti = "test-jti-123";
        mock.expect_has_token()
            .with(eq(jti))
            .times(1)
            .returning(|_| Box::pin(async move { Ok(true) }));

        assert_eq!(mock.has_token(jti).await.unwrap(), true);
    }

    #[tokio::test]
    async fn test_has_token_false() {
        let mut mock = MockSessionRepository::new();
        mock.expect_has_token()
            .with(eq("missing"))
            .times(1)
            .returning(|_| Box::pin(async move { Ok(false) }));

        assert_eq!(mock.has_token("missing").await.unwrap(), false);
    }

    #[tokio::test]
    async fn test_delete_token_success() {
        let mut mock = MockSessionRepository::new();
        let jti = "test-jti-123";
        mock.expect_delete_token()
            .with(eq(jti))
            .times(1)
            .returning(|_| Box::pin(async move { Ok(()) }));

        assert!(mock.delete_token(jti).await.is_ok());
    }

    #[tokio::test]
    async fn test_delete_token_error() {
        let mut mock = MockSessionRepository::new();
        mock.expect_delete_token()
            .returning(|_| Box::pin(async move { Err(AppError::Internal) }));

        assert!(mock.delete_token("bad").await.is_err());
    }
}
