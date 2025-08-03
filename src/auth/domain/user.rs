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
}

impl fmt::Display for UserStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            UserStatus::Unverified => "Unverified",
            UserStatus::Active => "Active",
            UserStatus::Banned => "Banned",
        };
        write!(f, "{}", name)
    }
}

#[derive(Debug)]
pub struct UserCredential {
    pub id: i64,
    pub full_name: String,
    pub email: String,
    pub status: UserStatus,
    pub password: String,
}

#[derive(Debug)]
pub struct User {
    pub id: i64,
    pub full_name: String,
    pub email: String,
    pub status: UserStatus,
    pub avatar: String,
}

pub struct OAuthUserProfile {
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}
