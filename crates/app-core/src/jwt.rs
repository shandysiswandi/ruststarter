//! A utility module for creating and validating JSON Web Tokens (JWTs).

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

#[cfg_attr(feature = "testing", mockall::automock)]
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
        encode(&header, &claims, &EncodingKey::from_secret(secret.as_ref())).map_err(|_| JwtError::TokenCreation)
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

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn create_test_config() -> JwtConfig {
        JwtConfig {
            access_secret: "test_access_secret_key_12345".to_string(),
            refresh_secret: "test_refresh_secret_key_12345".to_string(),
            generic_secret: "test_generic_secret_key_12345".to_string(),
            access_exp_secs: 3600,   // 1 hour
            refresh_exp_secs: 86400, // 24 hours
            generic_exp_secs: 1800,  // 30 minutes
            issuer: "test_issuer".to_string(),
            audience: "test_audience".to_string(),
        }
    }

    fn create_jwt_service() -> JwtService {
        JwtService::new(create_test_config())
    }

    #[test]
    fn test_create_token_success() {
        let service = create_jwt_service();
        let user_id = 123i64;

        let result_access_token = service.create_access_token(user_id);

        assert!(result_access_token.is_ok());
        let token = result_access_token.unwrap();
        assert!(!token.is_empty());
        assert!(token.contains("."));

        //

        let result_refresh_token = service.create_refresh_token(user_id);

        assert!(result_refresh_token.is_ok());
        let token = result_refresh_token.unwrap();
        assert!(!token.is_empty());
        assert!(token.contains("."));

        //

        let result_generic_token = service.create_generic_token(user_id);

        assert!(result_generic_token.is_ok());
        let token = result_generic_token.unwrap();
        assert!(!token.is_empty());
        assert!(token.contains("."));
    }

    #[test]
    fn test_validate_token_success() {
        let service = create_jwt_service();
        let user_id = 123i64;

        let access_token = service.create_access_token(user_id).unwrap();
        let result_access_token = service.validate_access_token(&access_token);

        assert!(result_access_token.is_ok());
        let claims = result_access_token.unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.iss, "test_issuer");
        assert_eq!(claims.aud, "test_audience");
        assert!(!claims.jti.is_empty());

        //

        let refresh_token = service.create_refresh_token(user_id).unwrap();
        let result_refresh_token = service.validate_refresh_token(&refresh_token);

        assert!(result_refresh_token.is_ok());
        let claims = result_refresh_token.unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.iss, "test_issuer");
        assert_eq!(claims.aud, "test_audience");
        assert!(!claims.jti.is_empty());

        //

        let generic_token = service.create_generic_token(user_id).unwrap();
        let result_generic_token = service.validate_generic_token(&generic_token);

        assert!(result_generic_token.is_ok());
        let claims = result_generic_token.unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.iss, "test_issuer");
        assert_eq!(claims.aud, "test_audience");
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn test_unique_jti_for_each_token() {
        let service = create_jwt_service();
        let user_id = 123i64;

        let token1 = service.create_access_token(user_id).unwrap();
        let token2 = service.create_access_token(user_id).unwrap();

        let claims1 = service.validate_access_token(&token1).unwrap();
        let claims2 = service.validate_access_token(&token2).unwrap();

        assert_ne!(claims1.jti, claims2.jti);
        assert_eq!(claims1.sub, claims2.sub); // Same user
    }

    #[test]
    fn test_claims_timestamps() {
        let service = create_jwt_service();
        let user_id = 123i64;

        let before_creation = Utc::now().timestamp() as usize;
        let token = service.create_access_token(user_id).unwrap();
        let after_creation = Utc::now().timestamp() as usize;

        let claims = service.validate_access_token(&token).unwrap();

        assert!(claims.iat >= before_creation);
        assert!(claims.iat <= after_creation);
        assert!(claims.exp > claims.iat);

        let expected_exp = claims.iat + service.config.access_exp_secs as usize;
        assert_eq!(claims.exp, expected_exp);
    }

    #[test]
    fn test_validate_token_with_wrong_secret() {
        let service = create_jwt_service();
        let user_id = 123i64;

        let token = service.create_access_token(user_id).unwrap();
        let result = service.validate_refresh_token(&token); // Using wrong validation method

        assert!(result.is_err());
        match result.unwrap_err() {
            JwtError::InvalidToken => (),
            _ => panic!("Expected InvalidToken error"),
        }
    }

    #[test]
    fn test_validate_malformed_token() {
        let service = create_jwt_service();
        let malformed_token = "not_a_valid_jwt_at_all";

        let result = service.validate_access_token(malformed_token);

        assert!(result.is_err());
        match result.unwrap_err() {
            JwtError::InvalidToken => (),
            _ => panic!("Expected InvalidToken error"),
        }
    }

    #[test]
    fn test_token_expiration() {
        let mut config = create_test_config();
        config.access_exp_secs = -1_000_000; // 1 second expiration
        let service = JwtService::new(config);
        let user_id = 123i64;

        let token = service.create_access_token(user_id).unwrap();
        let result = service.validate_access_token(&token);

        assert!(result.is_err());
        match result.unwrap_err() {
            JwtError::TokenExpired => (),
            _ => panic!("Expected TokenExpired error"),
        }
    }
}
