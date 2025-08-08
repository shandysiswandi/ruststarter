use crate::auth::domain::inout::prelude::*;
use crate::auth::inbound::model::prelude::*;
use crate::{
    app::{
        extractors::{AppJson, AppPath, AppQuery},
        response::{Meta, Response},
        state::AppState,
    },
    auth::domain::entity::user::UserStatus,
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
        .list_users(ListUsersInput {
            page: query.page,
            per_page: query.per_page,
        })
        .await
        .map(|output| {
            let users = output
                .users
                .into_iter()
                .map(UserResponse::from)
                .collect::<Vec<_>>();

            Response::with_meta(users, Meta::new(output.total, query.page, query.per_page))
        })
}

#[debug_handler]
pub async fn get_user(State(state): State<AppState>, AppPath(user_id): AppPath<i64>) -> impl IntoResponse {
    state
        .auth
        .authz
        .get_user(GetUserInput { user_id })
        .await
        .map(UserResponse::from)
        .map(Response::from)
}

#[debug_handler]
pub async fn update_user(
    State(state): State<AppState>,
    AppPath(user_id): AppPath<i64>,
    AppJson(req): AppJson<UpdateUserRequest>,
) -> impl IntoResponse {
    state
        .auth
        .authz
        .update_user(UpdateUserInput {
            id: user_id,
            email: req.email,
            full_name: req.full_name,
            status: req.status.map(UserStatus::from_string),
        })
        .await
        .map(|output| UpdateUserResponse {
            success: output.success,
        })
        .map(Response::from)
}

#[debug_handler]
pub async fn set_user_roles(
    State(state): State<AppState>,
    AppPath(user_id): AppPath<i64>,
    AppJson(req): AppJson<SetUserRolesRequest>,
) -> impl IntoResponse {
    state
        .auth
        .authz
        .set_user_roles(SetUserRolesInput {
            user_id,
            role_ids: req.role_ids,
        })
        .await
        .map(|output| SetUserRolesResponse {
            success: output.success,
        })
        .map(Response::from)
}
