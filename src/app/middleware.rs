//! Defines application-specific Axum middleware.

use std::time::Instant;

use crate::app::error::AppError;
use crate::app::jwt::Claims;
use crate::app::state::AppState;
use axum::{
    body::Body,
    extract::{FromRequestParts, State},
    http::{HeaderName, HeaderValue, Request, StatusCode, header, request::Parts},
    middleware::Next,
    response::Response,
};

impl FromRequestParts<AppState> for Claims {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &AppState) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Claims>()
            .cloned()
            .ok_or_else(|| AppError::Unauthorized("Authentication required.".to_string()))
    }
}

pub async fn auth(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| AppError::Unauthorized("Missing or invalid authorization header".to_string()))?;

    let claims = state.token.validate_access_token(token)?;

    let (mut parts, body) = req.into_parts();
    parts.extensions.insert(claims);
    let req = Request::from_parts(parts, body);

    Ok(next.run(req).await)
}

pub async fn request_response_logger(mut req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let start_time = Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let version = req.version();

    let mut c_id = String::default();
    if let Some(request_id) = req.headers().get("x-request-id") {
        if let Ok(id_str) = request_id.to_str() {
            c_id = id_str.to_string()
        }
    } else {
        c_id = uuid::Uuid::new_v4().to_string()
    }

    req.extensions_mut().insert(c_id.clone());

    tracing::info!(
        _cID = c_id,
        method = %method,
        uri = %uri,
        version = ?version,
        "Incoming request"
    );

    let mut response = next.run(req).await;

    let duration = start_time.elapsed();
    let status = response.status();

    response.headers_mut().insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(c_id.as_str())
            .unwrap_or_else(|_| HeaderValue::from_static("invalid-correlation-id")),
    );

    let log_level = if status.is_server_error() {
        "error"
    } else if status.is_client_error() {
        "warn"
    } else {
        "info"
    };

    match log_level {
        "error" => tracing::error!(
            _cID = c_id,
            method = %method,
            uri = %uri,
            status = %status,
            duration_ms = duration.as_millis(),
            "Request completed with server error"
        ),
        "warn" => tracing::warn!(
            _cID = c_id,
            method = %method,
            uri = %uri,
            status = %status,
            duration_ms = duration.as_millis(),
            "Request completed with client error"
        ),
        _ => tracing::info!(
            _cID = c_id,
            method = %method,
            uri = %uri,
            status = %status,
            duration_ms = duration.as_millis(),
            "Request completed successfully"
        ),
    }

    Ok(response)
}
