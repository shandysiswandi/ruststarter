//! A centralized and idiomatic error handling module for the Axum web
//! application.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bb8_redis::bb8;
use serde::Serialize;
use serde_json::json;
use thiserror::Error;

use super::config::ConfigError;
use super::crypto::CryptoError;
use super::jwt::JwtError;
use super::mail::MailerError;
use super::oauth::OAuthError;
use super::password::HashingError;
use super::storage::StorageError;
use super::uid::SnowflakeError;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Validation failed")]
    Validation(#[from] validator::ValidationErrors),

    #[error("Validation failed")]
    ValidationStr(String),

    #[error("Invalid request format: {0}")]
    RequestFormat(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    // Internal Libraries
    #[error("Config operation failed")]
    Config(#[from] ConfigError),

    #[error("Crypto operation failed")]
    Crypto(#[from] CryptoError),

    #[error("JWT operation failed")]
    Jwt(#[from] JwtError),

    #[error("Mail operation failed")]
    Mail(#[from] MailerError),

    #[error("OAuth operation failed")]
    OAuth(#[from] OAuthError),

    #[error("Password Hashing operation failed")]
    Hashing(#[from] HashingError),

    #[error("Storage operation failed")]
    Storage(#[from] StorageError),

    #[error("Snowflake operation failed")]
    IdGeneration(#[from] SnowflakeError),

    // Third Party Libraries
    #[error("Sea ORM operation failed")]
    Database(#[from] sea_orm::DbErr),

    #[error("Redis operation failed")]
    Redis(#[from] redis::RedisError),

    #[error("Redis connection pool operation failed")]
    RedisPool(#[from] bb8::RunError<redis::RedisError>),

    #[error("Multipart operation failed")]
    Multipart(#[from] axum::extract::multipart::MultipartError),

    #[error("Serde JSON operation failed")]
    JsonParse(#[from] serde_json::Error),

    #[error("TOTP secret is malformed")]
    TotpSecretMalformed(#[from] totp_rs::SecretParseError),

    #[error("TOTP URL operation failed")]
    TotpUrl(#[from] totp_rs::TotpUrlError),

    #[error("TOTP QR operation failed")]
    TotpQrGeneration(String),

    #[error("System Time operation failed")]
    TimeError(#[from] std::time::SystemTimeError),

    #[error("An internal server error occurred")]
    Internal,
}

#[derive(Serialize)]
struct ErrorResponse {
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, details) = match self {
            AppError::Validation(err) => {
                let details = json!(err.field_errors());
                (StatusCode::UNPROCESSABLE_ENTITY, "Validation failed".to_string(), Some(details))
            },
            AppError::RequestFormat(msg) => (StatusCode::BAD_REQUEST, msg, None),
            AppError::ValidationStr(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg, None),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg, None),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg, None),
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg, None),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg, None),

            // Internal Libraries
            AppError::Config(err) => {
                tracing::error!("Config getter error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },
            AppError::Crypto(err) => {
                tracing::error!("Config getter error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },
            AppError::Jwt(err) => {
                tracing::error!("JWT error: {:?}", err);
                let status = match err {
                    JwtError::TokenExpired | JwtError::InvalidToken => StatusCode::UNAUTHORIZED,
                    JwtError::TokenCreation => StatusCode::INTERNAL_SERVER_ERROR,
                };
                let message = match err {
                    JwtError::TokenExpired | JwtError::InvalidToken => err.to_string(),
                    JwtError::TokenCreation => "An internal server error occurred".to_string(),
                };
                (status, message, None)
            },
            AppError::Mail(err) => {
                tracing::error!("Mail server error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },
            AppError::OAuth(err) => {
                let status = match err {
                    OAuthError::InvalidUrl(_)
                    | OAuthError::TokenExchange(_)
                    | OAuthError::TokenRevocation(_)
                    | OAuthError::ProviderNotFound(_) => StatusCode::BAD_REQUEST,

                    OAuthError::HttpClient(_) | OAuthError::ProfileParse => StatusCode::BAD_GATEWAY,

                    OAuthError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
                };

                let message = match err {
                    OAuthError::InvalidUrl(_) | OAuthError::ProviderNotFound(_) => err.to_string(),
                    OAuthError::HttpClient(_) | OAuthError::ProfileParse => "OAuth provider unavailable".to_string(),
                    OAuthError::TokenExchange(_) | OAuthError::TokenRevocation(_) => {
                        "OAuth operation failed".to_string()
                    },
                    OAuthError::Internal => "An internal server error occurred".to_string(),
                };

                (status, message, None)
            },
            AppError::Hashing(err) => {
                tracing::error!("Password hashing error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },
            AppError::Storage(err) => {
                tracing::error!("Storage error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },
            AppError::IdGeneration(err) => {
                tracing::error!("ID generation error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },

            // Third Party Libraries
            AppError::Database(err) => {
                tracing::error!("Database error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },
            AppError::Redis(err) | AppError::RedisPool(bb8::RunError::User(err)) => {
                tracing::error!("Redis error: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },
            AppError::RedisPool(bb8::RunError::TimedOut) => {
                tracing::error!("Redis connection pool timed out");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },
            AppError::Multipart(err) => {
                tracing::warn!("Multipart request error: {:?}", err);
                (StatusCode::BAD_REQUEST, "Invalid multipart form data".to_string(), None)
            },
            AppError::JsonParse(err) => {
                tracing::error!("Failed to parse JSON: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },
            AppError::TotpSecretMalformed(err) => {
                tracing::error!("Failed to parse TOTP secret: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },
            AppError::TotpUrl(err) => {
                tracing::error!("Failed to generate TOTP URL: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },
            AppError::TotpQrGeneration(err) => {
                tracing::error!("Failed to parse system time: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },
            AppError::TimeError(err) => {
                tracing::error!("Failed to generate TOTP QR code: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },
            AppError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An internal server error occurred".to_string(),
                None,
            ),
        };

        (status, Json(ErrorResponse { message, details })).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use bb8_redis::bb8;
    use sea_orm::DbErr;
    use serde_json::Value;
    use validator::{ValidationError, ValidationErrors};

    use super::*;

    /// Helper function to extract JSON response body from an Axum response
    async fn extract_json_response(response: Response<Body>) -> (StatusCode, Value) {
        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("Failed to read response body");
        let json: Value = serde_json::from_slice(&body_bytes).expect("Failed to parse JSON response");
        (status, json)
    }

    /// Helper function to create validation errors for testing
    fn create_validation_errors() -> ValidationErrors {
        let mut errors = ValidationErrors::new();
        let mut email_error = ValidationError::new("email");
        email_error.message = Some("Invalid email format".into());
        errors.add("email", email_error);

        let mut password_error = ValidationError::new("length");
        password_error.message = Some("Password too short".into());
        errors.add("password", password_error);

        errors
    }

    #[tokio::test]
    async fn test_request_format_error() {
        let error = AppError::RequestFormat("Invalid JSON format".to_string());
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["message"], "Invalid JSON format");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_validation_error() {
        let validation_errors = create_validation_errors();
        let error = AppError::Validation(validation_errors);
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(json["message"], "Validation failed");
        assert!(!json["details"].is_null());

        // Check that details contain field errors
        let details = &json["details"];
        assert!(details["email"].is_array());
        assert!(details["password"].is_array());
    }

    #[tokio::test]
    async fn test_validation_str_error() {
        let error = AppError::ValidationStr("User not valid".to_string());
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(json["message"], "User not valid");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_unauthorized_error() {
        let error = AppError::Unauthorized("Invalid credentials".to_string());
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["message"], "Invalid credentials");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_forbidden_error() {
        let error = AppError::Forbidden("Access denied".to_string());
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(json["message"], "Access denied");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_not_found_error() {
        let error = AppError::NotFound("User not found".to_string());
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["message"], "User not found");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_conflict_error() {
        let error = AppError::Conflict("Email already exists".to_string());
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(json["message"], "Email already exists");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_storage_error() {
        let error = AppError::Storage(StorageError::Unknown);
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["message"], "An internal server error occurred");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_database_error() {
        let db_error = DbErr::UnpackInsertId;
        let error = AppError::Database(db_error);
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["message"], "An internal server error occurred");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_jwt_token_expired_error() {
        let jwt_error = JwtError::TokenExpired;
        let error = AppError::Jwt(jwt_error);
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["message"], "Token has expired");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_jwt_invalid_token_error() {
        let jwt_error = JwtError::InvalidToken;
        let error = AppError::Jwt(jwt_error);
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["message"], "Invalid token format or signature");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_jwt_token_creation_error() {
        let jwt_error = JwtError::TokenCreation;
        let error = AppError::Jwt(jwt_error);
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["message"], "An internal server error occurred");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_redis_error() {
        let redis_error = redis::RedisError::from((redis::ErrorKind::TypeError, "Type error"));
        let error = AppError::Redis(redis_error);
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["message"], "An internal server error occurred");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_redis_pool_timeout_error() {
        let pool_error = bb8::RunError::<redis::RedisError>::TimedOut;
        let error = AppError::RedisPool(pool_error);
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["message"], "An internal server error occurred");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_password_hashing_error() {
        let hash_error = HashingError::Hash(argon2::password_hash::Error::Algorithm);
        let error = AppError::Hashing(hash_error);
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["message"], "An internal server error occurred");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_unique_id_error() {
        let error = AppError::IdGeneration(SnowflakeError::IdOverflow);
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["message"], "An internal server error occurred");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_config_error() {
        let error = AppError::Config(ConfigError::LockPoisoned);
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["message"], "An internal server error occurred");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_totp_url_error() {
        let error = AppError::TotpUrl(totp_rs::TotpUrlError::Algorithm("errror".to_string()));
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["message"], "An internal server error occurred");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_totp_secret_error() {
        let error = AppError::TotpSecretMalformed(totp_rs::SecretParseError::ParseBase32);
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["message"], "An internal server error occurred");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_json_parse_error() {
        let json_error = serde_json::from_str::<Value>("invalid json").unwrap_err();
        let error = AppError::JsonParse(json_error);
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["message"], "An internal server error occurred");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_internal_error() {
        let error = AppError::Internal;
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["message"], "An internal server error occurred");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_time_error() {
        // Create a SystemTimeError by going backwards in time
        use std::time::{Duration, UNIX_EPOCH};
        let time_error = (UNIX_EPOCH - Duration::from_secs(1)).duration_since(UNIX_EPOCH).unwrap_err();
        let error = AppError::TimeError(time_error);
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["message"], "An internal server error occurred");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_totp_qr_generation_error() {
        let error = AppError::TotpQrGeneration("Failed to generate QR code".to_string());
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["message"], "An internal server error occurred");
        assert!(json["details"].is_null());
    }

    #[tokio::test]
    async fn test_validation_error_structure() {
        let mut errors = ValidationErrors::new();

        // Add multiple errors for the same field
        let mut email_error1 = ValidationError::new("email");
        email_error1.message = Some("Invalid email format".into());
        errors.add("email", email_error1);

        let mut email_error2 = ValidationError::new("required");
        email_error2.message = Some("Email is required".into());
        errors.add("email", email_error2);

        let error = AppError::Validation(errors);
        let response = error.into_response();
        let (status, json) = extract_json_response(response).await;

        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(json["message"], "Validation failed");

        let details = &json["details"];
        assert!(details["email"].is_array());
        assert_eq!(details["email"].as_array().unwrap().len(), 2);
    }
}
