use std::fmt;

use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserStatus {
    Unverified,
    Active,
    Banned,
}

impl UserStatus {
    pub fn from_i16(status_code: i16) -> Self {
        match status_code {
            1 => UserStatus::Active,
            2 => UserStatus::Banned,
            _ => UserStatus::Unverified,
        }
    }
}

impl From<String> for UserStatus {
    fn from(value: String) -> Self {
        match value.to_lowercase().as_str() {
            "active" => UserStatus::Active,
            "banned" => UserStatus::Banned,
            _ => UserStatus::Unverified,
        }
    }
}

impl fmt::Display for UserStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            UserStatus::Unverified => "Unverified",
            UserStatus::Active => "Active",
            UserStatus::Banned => "Banned",
        };
        write!(f, "{name}")
    }
}

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub full_name: String,
    pub avatar_url: Option<String>,
    pub status: UserStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn new(id: i64, email: String, full_name: String, avatar_url: Option<String>, status: UserStatus) -> Self {
        Self {
            id,
            email,
            full_name,
            avatar_url,
            status,
            created_at: DateTime::default(), // UNIX_EPOCH (1970-01-01 UTC)
            updated_at: DateTime::default(), // UNIX_EPOCH (1970-01-01 UTC)
        }
    }
}

#[derive(Debug)]
pub struct UserUpdatePayload {
    pub id: i64,
    pub email: Option<String>,
    pub full_name: Option<String>,
    pub avatar_url: Option<String>,
    pub status: Option<UserStatus>,
}

#[derive(Debug)]
pub struct NewUser {
    pub id: i64,
    pub email: String,
    pub full_name: String,
    pub status: UserStatus,
    pub password: String,
    pub verify_token: String,
    pub verify_expiry: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    #[test]
    fn test_user_status_from_i16() {
        assert_eq!(UserStatus::from_i16(1), UserStatus::Active);
        assert_eq!(UserStatus::from_i16(2), UserStatus::Banned);
        assert_eq!(UserStatus::from_i16(99), UserStatus::Unverified);
        assert_eq!(UserStatus::from_i16(0), UserStatus::Unverified);
    }

    #[test]
    fn test_user_status_from_string() {
        assert_eq!(UserStatus::from("active".to_string()), UserStatus::Active);
        assert_eq!(UserStatus::from("Active".to_string()), UserStatus::Active);
        assert_eq!(UserStatus::from("banned".to_string()), UserStatus::Banned);
        assert_eq!(UserStatus::from("BANNED".to_string()), UserStatus::Banned);
        assert_eq!(UserStatus::from("unknown".to_string()), UserStatus::Unverified);
    }

    #[test]
    fn test_user_status_display() {
        assert_eq!(format!("{}", UserStatus::Unverified), "Unverified");
        assert_eq!(format!("{}", UserStatus::Active), "Active");
        assert_eq!(format!("{}", UserStatus::Banned), "Banned");
    }

    #[test]
    fn test_user_new() {
        let user = User::new(
            1,
            "test@example.com".to_string(),
            "Test User".to_string(),
            Some("http://avatar.url".to_string()),
            UserStatus::Active,
        );

        assert_eq!(user.id, 1);
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.full_name, "Test User");
        assert_eq!(user.avatar_url, Some("http://avatar.url".to_string()));
        assert_eq!(user.status, UserStatus::Active);

        // Default timestamps should not be in the future
        let now = Utc::now();
        assert!(user.created_at <= now);
        assert!(user.updated_at <= now);
    }
}
