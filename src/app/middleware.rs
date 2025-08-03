//! Defines application-specific Axum middleware.

use crate::app::error::AppError;
use crate::app::jwt::Claims;
use crate::app::state::AppState;
use axum::{
    body::Body,
    extract::{FromRequestParts, State},
    http::{Request, header, request::Parts},
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
