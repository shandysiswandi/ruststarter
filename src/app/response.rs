//! Defines a generic and structured wrapper for successful JSON API responses.

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;

/// A structured container for pagination metadata.
#[derive(Serialize)]
pub struct Meta {
    pub total_items: u64,
    pub current_page: u64,
    pub per_page: u64,
    pub total_pages: u64,
}

/// A generic container for all successful API responses.
#[derive(Serialize)]
pub struct Response<T> {
    message: String,
    data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<Meta>,
}

impl<T> Response<T> {
    pub fn new(data: T) -> Self {
        Self {
            message: "successfully".to_string(),
            data,
            meta: None,
        }
    }

    pub fn with_message(data: T, message: &str) -> Self {
        Self {
            message: message.to_string(),
            data,
            meta: None,
        }
    }

    pub fn with_pagination(data: T, message: &str, meta: Meta) -> Self {
        Self {
            message: message.to_string(),
            data,
            meta: Some(meta),
        }
    }
}

impl<T: Serialize> IntoResponse for Response<T> {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}
