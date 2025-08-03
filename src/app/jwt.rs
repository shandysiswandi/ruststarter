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

pub struct JwtService {
    access_secret: String,
    refresh_secret: String,
    generic_secret: String,
    access_exp_secs: i64,
    refresh_exp_secs: i64,
    generic_exp_secs: i64,
    issuer: String,
    audience: String,
}

impl JwtService {
    pub fn new(
        access_secret: String,
        refresh_secret: String,
        generic_secret: String,
        access_exp_secs: i64,
        refresh_exp_secs: i64,
        generic_exp_secs: i64,
        issuer: String,
        audience: String,
    ) -> Self {
        Self {
            access_secret,
            refresh_secret,
            generic_secret,
            access_exp_secs,
            refresh_exp_secs,
            generic_exp_secs,
            issuer,
            audience,
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
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            exp,
            iat,
        };

        let header = Header::new(Algorithm::HS512);
        encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref()))
            .map_err(|_| JwtError::TokenCreation)
    }

    fn validate_token(&self, token: &str, secret: &str) -> Result<Claims, JwtError> {
        let mut validation = Validation::new(Algorithm::HS512);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);

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
        self.create_token(user_id, &self.access_secret, self.access_exp_secs)
    }

    fn create_refresh_token(&self, user_id: i64) -> Result<String, JwtError> {
        self.create_token(user_id, &self.refresh_secret, self.refresh_exp_secs)
    }

    fn create_generic_token(&self, user_id: i64) -> Result<String, JwtError> {
        self.create_token(user_id, &self.generic_secret, self.generic_exp_secs)
    }

    fn validate_access_token(&self, token: &str) -> Result<Claims, JwtError> {
        self.validate_token(token, &self.access_secret)
    }

    fn validate_refresh_token(&self, token: &str) -> Result<Claims, JwtError> {
        self.validate_token(token, &self.refresh_secret)
    }

    fn validate_generic_token(&self, token: &str) -> Result<Claims, JwtError> {
        self.validate_token(token, &self.generic_secret)
    }
}
