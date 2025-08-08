use chrono::{DateTime, Utc};

#[derive(Debug)]
pub struct UserCredential {
    pub user_id: i64,
    pub password: String,
    pub password_last_changed_at: DateTime<Utc>,
}
