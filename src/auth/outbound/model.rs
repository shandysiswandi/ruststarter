use crate::auth::domain::{connection, mfa, user};

// --- User Models ---

#[derive(sqlx::FromRow)]
pub struct UserCredentialModel {
    pub id: i64,
    pub full_name: String,
    pub email: String,
    pub status: i16,
    pub password: String,
}

impl From<UserCredentialModel> for user::User {
    fn from(result: UserCredentialModel) -> Self {
        Self {
            id: result.id,
            full_name: result.full_name,
            email: result.email,
            status: user::UserStatus::from_i16(result.status),
            password: result.password,
        }
    }
}

#[derive(sqlx::FromRow)]
pub struct UserModel {
    pub id: i64,
    pub email: String,
    pub avatar_url: String,
    pub full_name: String,
    pub status: i16,
}

impl From<UserModel> for user::User {
    fn from(result: UserModel) -> Self {
        Self {
            id: result.id,
            full_name: result.full_name,
            email: result.email,
            status: user::UserStatus::from_i16(result.status),
            password: "***".to_string(),
        }
    }
}

// --- MFA Models ---

#[derive(sqlx::FromRow)]
pub struct MfaFactorModel {
    pub id: i64,
    #[sqlx(rename = "type")]
    pub mfa_type: i16,
    pub friendly_name: String,
    pub secret: String,
}

impl From<MfaFactorModel> for mfa::MfaFactor {
    fn from(result: MfaFactorModel) -> Self {
        Self {
            id: result.id,
            mfa_type: mfa::MfaFactorType::from_i16(result.mfa_type),
            friendly_name: result.friendly_name,
            secret: result.secret,
        }
    }
}

//
#[derive(sqlx::FromRow)]
pub struct ConnectionModel {
    pub id: i64,
    pub provider: String,
    pub provider_user_id: String,
}

impl From<ConnectionModel> for connection::Connection {
    fn from(result: ConnectionModel) -> Self {
        Self {
            id: result.id,
            provider: result.provider,
            provider_user_id: result.provider_user_id,
        }
    }
}
