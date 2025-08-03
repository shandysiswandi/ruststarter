//! A centralized and idiomatic error handling module for the Axum web application.
//!
//! This module defines a single `AppError` enum that consolidates all possible errors
//! within the application, from database issues and validation failures to custom

//! business logic errors. By implementing `axum::response::IntoResponse`, this
//! error type can be returned directly from any handler, simplifying error logic
//! throughout the codebase.

use axum::{
    Json,
    extract::multipart::MultipartError,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use bb8_redis::bb8;
use serde::Serialize;
use serde_json::json;
use thiserror::Error;
use totp_rs::{SecretParseError, TotpUrlError};
use validator::ValidationErrors;

use crate::app::{jwt::JwtError, uid::SnowflakeError};

use super::password::HashingError;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Validation failed")]
    Validation(#[from] ValidationErrors),

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

    #[error("An internal database error occurred")]
    Database(#[from] sqlx::Error),

    #[error("An internal error occurred during password hashing")]
    Hashing(#[from] HashingError),

    #[error("Failed to generate unique ID")]
    IdGeneration(#[from] SnowflakeError),

    #[error("JWT operation failed")]
    Jwt(#[from] JwtError),

    #[error("Redis operation failed")]
    Redis(#[from] redis::RedisError),

    #[error("Redis connection pool error")]
    RedisPool(#[from] bb8::RunError<redis::RedisError>),

    #[error("Multipart request error")]
    Multipart(#[from] MultipartError),

    #[error("Failed to parse JSON")]
    JsonParse(#[from] serde_json::Error),

    #[error("A TOTP secret is malformed")]
    TotpSecretMalformed(#[from] SecretParseError),

    #[error("Failed to generate TOTP URL for QR code")]
    TotpUrl(#[from] TotpUrlError),

    #[error("Failed to generate QR code image")]
    TotpQrGeneration(String),

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
            AppError::RequestFormat(msg) => (StatusCode::BAD_REQUEST, msg, None),

            AppError::Validation(err) => {
                let details = json!(err.field_errors());
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Validation failed".to_string(),
                    Some(details),
                )
            },

            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg, None),

            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg, None),

            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg, None),

            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg, None),

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

            AppError::Multipart(err) => {
                tracing::warn!("Multipart request error: {:?}", err);
                (
                    StatusCode::BAD_REQUEST,
                    "Invalid multipart form data".to_string(),
                    None,
                )
            },

            AppError::JsonParse(err) => {
                tracing::error!("Failed to parse JSON: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },

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

            AppError::Hashing(err) => {
                tracing::error!("Password hashing error: {:?}", err);
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
                tracing::error!("Failed to generate TOTP QR code: {:?}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occurred".to_string(),
                    None,
                )
            },

            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "An internal server error occurred".to_string(),
                None,
            ),
        };

        (status, Json(ErrorResponse { message, details })).into_response()
    }
}
