//! A utility module for handling Axum's extractor rejections.

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};

use super::error::AppError;

impl From<JsonRejection> for AppError {
    fn from(rejection: JsonRejection) -> Self {
        AppError::RequestFormat(rejection.to_string())
    }
}

impl From<PathRejection> for AppError {
    fn from(rejection: PathRejection) -> Self {
        AppError::RequestFormat(rejection.to_string())
    }
}

impl From<QueryRejection> for AppError {
    fn from(rejection: QueryRejection) -> Self {
        AppError::RequestFormat(rejection.to_string())
    }
}
