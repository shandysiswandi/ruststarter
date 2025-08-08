//! A utility module for creating and validating JSON Web Tokens (JWTs).
//!
//! This module provides a `TokenManager` trait and a concrete `JwtService`
//! implementation for handling JWT operations in a testable and modular way.

use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum JwtError {
    #[error("Token has expired")]
    TokenExpired,

    #[error("Invalid token format or signature")]
    InvalidToken,

    #[error("Failed to create token")]
    TokenCreation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i64,
    pub jti: String,
    pub iss: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
}

#[cfg_attr(test, mockall::automock)]
pub trait TokenManager: Send + Sync {
    fn create_access_token(&self, user_id: i64) -> Result<String, JwtError>;
    fn create_refresh_token(&self, user_id: i64) -> Result<String, JwtError>;
    fn create_generic_token(&self, user_id: i64) -> Result<String, JwtError>;
    fn validate_access_token(&self, token: &str) -> Result<Claims, JwtError>;
    fn validate_refresh_token(&self, token: &str) -> Result<Claims, JwtError>;
    fn validate_generic_token(&self, token: &str) -> Result<Claims, JwtError>;
}

pub struct JwtConfig {
    pub access_secret: String,
    pub refresh_secret: String,
    pub generic_secret: String,
    pub access_exp_secs: i64,
    pub refresh_exp_secs: i64,
    pub generic_exp_secs: i64,
    pub issuer: String,
    pub audience: String,
}

pub struct JwtService {
    config: JwtConfig,
}

impl JwtService {
    pub fn new(config: JwtConfig) -> Self {
        Self {
            config: JwtConfig {
                access_secret: config.access_secret,
                refresh_secret: config.refresh_secret,
                generic_secret: config.generic_secret,
                access_exp_secs: config.access_exp_secs,
                refresh_exp_secs: config.refresh_exp_secs,
                generic_exp_secs: config.generic_exp_secs,
                issuer: config.issuer,
                audience: config.audience,
            },
        }
    }

    fn create_token(&self, user_id: i64, secret: &str, expires_in_secs: i64) -> Result<String, JwtError> {
        let now = Utc::now();
        let expires_in = Duration::seconds(expires_in_secs);
        let exp = (now + expires_in).timestamp() as usize;
        let iat = now.timestamp() as usize;

        let claims = Claims {
            sub: user_id,
            jti: Uuid::new_v4().to_string(),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            exp,
            iat,
        };

        let header = Header::new(Algorithm::HS512);
        encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))
            .map_err(|_| JwtError::TokenCreation)
    }

    fn validate_token(&self, token: &str, secret: &str) -> Result<Claims, JwtError> {
        let mut validation = Validation::new(Algorithm::HS512);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);

        decode::<Claims>(token, &DecodingKey::from_secret(secret.as_ref()), &validation)
            .map(|data| data.claims)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::TokenExpired,
                _ => JwtError::InvalidToken,
            })
    }
}

impl TokenManager for JwtService {
    fn create_access_token(&self, user_id: i64) -> Result<String, JwtError> {
        self.create_token(user_id, &self.config.access_secret, self.config.access_exp_secs)
    }

    fn create_refresh_token(&self, user_id: i64) -> Result<String, JwtError> {
        self.create_token(user_id, &self.config.refresh_secret, self.config.refresh_exp_secs)
    }

    fn create_generic_token(&self, user_id: i64) -> Result<String, JwtError> {
        self.create_token(user_id, &self.config.generic_secret, self.config.generic_exp_secs)
    }

    fn validate_access_token(&self, token: &str) -> Result<Claims, JwtError> {
        self.validate_token(token, &self.config.access_secret)
    }

    fn validate_refresh_token(&self, token: &str) -> Result<Claims, JwtError> {
        self.validate_token(token, &self.config.refresh_secret)
    }

    fn validate_generic_token(&self, token: &str) -> Result<Claims, JwtError> {
        self.validate_token(token, &self.config.generic_secret)
    }
}
