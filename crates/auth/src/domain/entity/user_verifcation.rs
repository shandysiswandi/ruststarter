use chrono::{DateTime, Utc};

#[derive(Debug)]
pub struct UserVerification {
    #[allow(dead_code)]
    pub user_id: i64,
    #[allow(dead_code)]
    pub token: String,
    pub expires_at: DateTime<Utc>,
}
