//! Defines application-specific Axum middleware.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderName, HeaderValue, Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;

use super::error::AppError;
use super::jwt::Claims;
use crate::jwt::TokenManager;

impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Claims>()
            .cloned()
            .ok_or_else(|| AppError::Unauthorized("Authentication required.".to_string()))
    }
}

pub async fn auth(
    State(tm): State<Arc<dyn TokenManager>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(|| AppError::Unauthorized("Missing or invalid authorization header".to_string()))?;

    let claims = tm.validate_access_token(token)?;

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
        HeaderValue::from_str(c_id.as_str()).unwrap_or_else(|_| HeaderValue::from_static("invalid-correlation-id")),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Method, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Router, middleware};
    use tower::ServiceExt;

    use super::*;
    use crate::jwt::{Claims, JwtError, MockTokenManager, TokenManager};

    async fn test_handler(claims: Claims) -> impl IntoResponse {
        format!("Hello, user: {}", claims.sub)
    }

    #[tokio::test]
    async fn test_auth_success() {
        // Create a mock TokenManager
        let mut tm = MockTokenManager::new();

        // Setup the mock to return valid claims for "valid_token"
        tm.expect_validate_access_token()
            .withf(|token| token == "valid_token")
            .returning(|_token| {
                Ok(Claims { sub: 123, exp: 9999999999, jti: "".into(), iss: "".into(), aud: "".into(), iat: 1 })
            });

        let tm: Arc<dyn TokenManager> = Arc::new(tm);

        let app = Router::new()
            .route("/protected", get(test_handler))
            .route_layer(middleware::from_fn_with_state(tm.clone(), auth))
            .with_state(tm.clone());

        let request = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/protected")
            .header("authorization", "Bearer valid_token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert_eq!(body_str, "Hello, user: 123");
    }

    #[tokio::test]
    async fn test_auth_error() {
        // Create a mock TokenManager
        let mut tm = MockTokenManager::new();

        // Setup the mock to return valid claims for "valid_token"
        tm.expect_validate_access_token().returning(|_| Err(JwtError::InvalidToken));

        let tm: Arc<dyn TokenManager> = Arc::new(tm);

        let app = Router::new()
            .route("/protected", get(test_handler))
            .route_layer(middleware::from_fn_with_state(tm.clone(), auth))
            .with_state(tm.clone());

        let request = axum::http::Request::builder()
            .method(Method::GET)
            .uri("/protected")
            .header("authorization", "Bearer invalid_token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
