use chrono::{DateTime, Utc};

#[derive(Debug)]
pub struct UserConnection {
    pub id: i64,
    pub user_id: i64,
    pub provider: String,
    pub provider_user_id: String,
    pub created_at: DateTime<Utc>,
}
