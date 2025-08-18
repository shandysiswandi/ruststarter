//! Defines custom Axum extractors for the application.

use axum::body::Body;
use axum::extract::{FromRequest, FromRequestParts, Json, Path, Query};
use axum::http::Request;
use axum::http::request::Parts;
use serde::de::DeserializeOwned;

use super::error::AppError;

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

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::extract::FromRequestParts;
    use axum::http::{Method, Request, StatusCode, Uri};
    use serde::{Deserialize, Serialize};
    use tower::ServiceExt;

    use super::*;

    // Test structs for deserialization
    #[derive(Debug, Deserialize, Serialize, PartialEq)]
    struct TestQuery {
        name: String,
        age: u32,
        active: Option<bool>,
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq)]
    struct TestPath {
        id: u64,
        slug: String,
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq)]
    struct TestJson {
        title: String,
        count: i32,
        tags: Vec<String>,
    }

    /// Helper function to create a mock state for testing
    fn mock_state() -> () {
        ()
    }

    #[tokio::test]
    async fn test_app_query_success() {
        let uri = "/test?name=john&age=25&active=true".parse::<Uri>().unwrap();
        let request = Request::builder().uri(uri).method(Method::GET).body(Body::empty()).unwrap();

        let (mut parts, _) = request.into_parts();
        let state = mock_state();

        let result = AppQuery::<TestQuery>::from_request_parts(&mut parts, &state).await;

        assert!(result.is_ok());
        let AppQuery(query) = result.unwrap();
        assert_eq!(query.name, "john");
        assert_eq!(query.age, 25);
        assert_eq!(query.active, Some(true));
    }

    #[tokio::test]
    async fn test_app_query_error() {
        let uri = "/test?name=john".parse::<Uri>().unwrap(); // missing 'age' field
        let request = Request::builder().uri(uri).method(Method::GET).body(Body::empty()).unwrap();

        let (mut parts, _) = request.into_parts();
        let state = mock_state();

        let result = AppQuery::<TestQuery>::from_request_parts(&mut parts, &state).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_app_path_success() {
        let app = Router::new().route(
            "/items/{id}/{slug}",
            axum::routing::get(|AppPath(params): AppPath<TestPath>| async move {
                format!("id: {}, slug: {}", params.id, params.slug)
            }),
        );

        let request = Request::builder()
            .uri("/items/123/hello-world")
            .body(axum::body::Body::empty())
            .expect("failed to build request testing");

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_app_path_error() {
        let app = Router::new().route(
            "/items/{id}",
            axum::routing::get(|AppPath(params): AppPath<TestPath>| async move {
                format!("id: {}, slug: {}", params.id, params.slug)
            }),
        );

        let request = Request::builder()
            .uri("/items/123")
            .body(axum::body::Body::empty())
            .expect("failed to build request testing");

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_app_json_success() {
        let json_data =
            TestJson { title: "Test Title".to_string(), count: 42, tags: vec!["rust".to_string(), "axum".to_string()] };
        let json_body = serde_json::to_string(&json_data).unwrap();

        let request = Request::builder()
            .method(Method::POST)
            .header("content-type", "application/json")
            .body(Body::from(json_body))
            .unwrap();

        let state = mock_state();
        let result = AppJson::<TestJson>::from_request(request, &state).await;

        assert!(result.is_ok());
        let AppJson(parsed) = result.unwrap();
        assert_eq!(parsed, json_data);
    }

    #[tokio::test]
    async fn test_app_json_error() {
        let invalid_json = "{invalid json}";

        let request = Request::builder()
            .method(Method::POST)
            .header("content-type", "application/json")
            .body(Body::from(invalid_json))
            .unwrap();

        let state = mock_state();
        let result = AppJson::<TestJson>::from_request(request, &state).await;

        assert!(result.is_err());
    }
}
