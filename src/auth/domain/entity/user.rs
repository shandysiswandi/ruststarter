use chrono::{DateTime, Utc};
use std::fmt;

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

    pub fn from_string(sts: String) -> Self {
        match sts.to_lowercase().as_str() {
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

#[derive(Debug)]
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
    pub fn new(
        id: i64,
        email: String,
        full_name: String,
        avatar_url: Option<String>,
        status: UserStatus,
    ) -> Self {
        Self {
            id,
            email,
            full_name,
            avatar_url,
            status,
            created_at: DateTime::default(),
            updated_at: DateTime::default(),
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
