//! Defines custom Axum extractors for the application.
//!
//! This module provides wrappers around Axum's built-in extractors to ensure
//! that any rejection is automatically converted into the application's standard
//! `AppError` JSON response, keeping handler signatures clean.

use crate::app::error::AppError;
use axum::{
    body::Body,
    extract::{FromRequest, FromRequestParts, Json, Path, Query},
    http::{Request, request::Parts},
};
use serde::de::DeserializeOwned;

pub struct AppQuery<T>(pub T);

impl<T, S> FromRequestParts<S> for AppQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(value)) => Ok(Self(value)),
            Err(rejection) => Err(AppError::from(rejection)),
        }
    }
}

pub struct AppPath<T>(pub T);

impl<T, S> FromRequestParts<S> for AppPath<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Path::<T>::from_request_parts(parts, state).await {
            Ok(Path(value)) => Ok(Self(value)),
            Err(rejection) => Err(AppError::from(rejection)),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AppJson<T>(pub T);

impl<T, S> FromRequest<S> for AppJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state).await?;
        Ok(Self(value))
    }
}
