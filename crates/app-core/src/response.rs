//! Defines a generic and structured wrapper for successful JSON API responses.

use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
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
        Self { total_items, current_page, per_page, total_pages: (total_items as f64 / per_page as f64).ceil() as u64 }
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
        Self { message: message.to_string(), data, meta: None }
    }

    pub fn with_meta(data: T, meta: Meta) -> Self {
        Self { message: "Successfully".to_string(), data, meta: Some(meta) }
    }
}

impl<T> From<T> for Response<T> {
    fn from(data: T) -> Self {
        Self { message: "Successfully".to_string(), data, meta: None }
    }
}

impl<T: Serialize> IntoResponse for Response<T> {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::response::IntoResponse;
    use serde_json::{Value, json};

    use super::*;

    #[test]
    fn test_meta_new() {
        let meta = Meta::new(25, 1, 10);
        assert_eq!(meta.total_items, 25);
        assert_eq!(meta.current_page, 1);
        assert_eq!(meta.per_page, 10);
        assert_eq!(meta.total_pages, 3);
    }

    #[test]
    fn test_response_with_message() {
        let resp = Response::with_message("data_value", "Custom message");
        assert_eq!(resp.message, "Custom message");
        assert_eq!(resp.data, "data_value");
        assert!(resp.meta.is_none());
    }

    #[test]
    fn test_response_with_meta() {
        let meta = Meta::new(50, 2, 25);
        let resp = Response::with_meta("some_data", meta);
        assert_eq!(resp.message, "Successfully");
        assert_eq!(resp.data, "some_data");
        assert!(resp.meta.is_some());
    }

    #[test]
    fn test_response_from() {
        let resp: Response<&str> = Response::from("abc");
        assert_eq!(resp.message, "Successfully");
        assert_eq!(resp.data, "abc");
        assert!(resp.meta.is_none());
    }

    #[tokio::test]
    async fn test_response_into_response() {
        let resp = Response::with_message("abc", "Hello!");
        let http_resp = resp.into_response();

        assert_eq!(http_resp.status(), StatusCode::OK);

        let body_bytes = to_bytes(http_resp.into_body(), usize::MAX).await.unwrap();
        let json_val: Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(json_val["message"], json!("Hello!"));
        assert_eq!(json_val["data"], json!("abc"));
        assert!(json_val.get("meta").is_none());
    }
}
