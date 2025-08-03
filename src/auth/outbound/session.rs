use crate::app::error::AppError;
use async_trait::async_trait;
use bb8_redis::{RedisConnectionManager, bb8};
use redis::AsyncCommands;

#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait SessionRepository: Send + Sync {
    async fn add_token(&self, jti: &str, exp_secs: u64) -> Result<(), AppError>;
    async fn has_token(&self, jti: &str) -> Result<bool, AppError>;
    async fn delete_token(&self, jti: &str) -> Result<(), AppError>;
}

pub struct SessionRedis {
    pool: bb8::Pool<RedisConnectionManager>,
}

impl SessionRedis {
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
