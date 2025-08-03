use crate::{
    app::{extractors::AppQuery, response::Response, state::AppState},
    auth::inbound::authz_model::{ListUsersRequest, UserResponse},
};
use axum::{debug_handler, extract::State, response::IntoResponse};

#[debug_handler]
pub async fn list_users(
    State(state): State<AppState>,
    AppQuery(query): AppQuery<ListUsersRequest>,
) -> impl IntoResponse {
    state
        .auth
        .authz
        .list_users()
        .await
        .map(|out| {
            out.users.into_iter().map(UserResponse::from).collect::<Vec<_>>();
        })
        .map(|out| Response::with_pagination(out.users, "Users retrieved successfully", meta))
}
