//! Defines a generic and structured wrapper for successful JSON API responses.

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;

#[derive(Serialize)]
pub struct Meta {
    pub total_items: u64,
    pub current_page: u64,
    pub per_page: u64,
    pub total_pages: u64,
}

impl Meta {
    pub fn new(total_items: u64, current_page: u64, per_page: u64) -> Self {
        Self {
            total_items,
            current_page,
            per_page,
            total_pages: (total_items as f64 / per_page as f64).ceil() as u64,
        }
    }
}

#[derive(Serialize)]
pub struct Response<T> {
    message: String,
    data: T,

    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<Meta>,
}

impl<T> Response<T> {
    pub fn with_message(data: T, message: &str) -> Self {
        Self {
            message: message.to_string(),
            data,
            meta: None,
        }
    }

    pub fn with_meta(data: T, meta: Meta) -> Self {
        Self {
            message: "Successfully".to_string(),
            data,
            meta: Some(meta),
        }
    }
}

impl<T> From<T> for Response<T> {
    fn from(data: T) -> Self {
        Self {
            message: "Successfully".to_string(),
            data,
            meta: None,
        }
    }
}

impl<T: Serialize> IntoResponse for Response<T> {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}
