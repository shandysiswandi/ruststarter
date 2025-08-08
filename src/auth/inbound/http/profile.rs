use crate::app::extractors::{AppJson, AppPath};
use crate::app::jwt::Claims;
use crate::app::response::Response;
use crate::app::state::AppState;
use crate::auth::domain::inout::prelude::*;
use crate::auth::inbound::model::prelude::*;
use axum::{Json, debug_handler, extract::Multipart, extract::State, response::IntoResponse};

#[debug_handler]
pub async fn get_profile(State(state): State<AppState>, claims: Claims) -> impl IntoResponse {
    state
        .auth
        .profile
        .get_profile(GetProfileInput { user_id: claims.sub })
        .await
        .map(|output| GetProfileResponse {
            id: output.id,
            email: output.email,
            full_name: output.full_name,
            avatar_url: output.avatar,
            created_at: output.created_at.to_rfc3339(),
            updated_at: output.updated_at.to_rfc3339(),
        })
        .map(Response::from)
}

#[debug_handler]
pub async fn update_profile(
    State(state): State<AppState>,
    claims: Claims,
    multipart: Multipart,
) -> impl IntoResponse {
    let req = UpdateProfileRequest::from_multipart(multipart).await?;

    state
        .auth
        .profile
        .update_profile(UpdateProfileInput {
            user_id: claims.sub,
            full_name: req.full_name,
            avatar: req.avatar,
        })
        .await
        .map(|output| UpdateProfileResponse {
            success: output.success,
        })
        .map(Response::from)
}

#[debug_handler]
pub async fn change_password(
    State(state): State<AppState>,
    claims: Claims,
    Json(req): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    state
        .auth
        .profile
        .change_password(ChangePasswordInput {
            user_id: claims.sub,
            old_password: req.old_password,
            new_password: req.new_password,
        })
        .await
        .map(|output| ChangePasswordResponse {
            success: output.success,
        })
        .map(Response::from)
}

#[debug_handler]
pub async fn list_connections(State(state): State<AppState>, claims: Claims) -> impl IntoResponse {
    state
        .auth
        .profile
        .list_connections(ListConnectionInput { user_id: claims.sub })
        .await
        .map(|user_connections| {
            user_connections
                .into_iter()
                .map(ConnectionResponse::from)
                .collect::<Vec<_>>()
        })
        .map(Response::from)
}

#[debug_handler]
pub async fn delete_connection(
    State(state): State<AppState>,
    claims: Claims,
    AppPath(connection_id): AppPath<i64>,
) -> impl IntoResponse {
    state
        .auth
        .profile
        .delete_connection(DeleteConnectionInput {
            user_id: claims.sub,
            connection_id,
        })
        .await
        .map(|output| DeleteConnectionResponse {
            success: output.success,
        })
        .map(Response::from)
}

#[debug_handler]
pub async fn list_mfa_factors(State(state): State<AppState>, claims: Claims) -> impl IntoResponse {
    state
        .auth
        .profile
        .list_mfa_factors(ListMfaFactorInput { user_id: claims.sub })
        .await
        .map(|mfa_factors| {
            mfa_factors
                .into_iter()
                .map(MfaFactorResponse::from)
                .collect::<Vec<_>>()
        })
        .map(Response::from)
}

#[debug_handler]
pub async fn delete_mfa_factor(
    State(state): State<AppState>,
    claims: Claims,
    AppPath(factor_id): AppPath<i64>,
) -> impl IntoResponse {
    state
        .auth
        .profile
        .delete_mfa_factor(DeleteMfaFactorInput {
            user_id: claims.sub,
            mfa_factor_id: factor_id,
        })
        .await
        .map(|output| DeleteMfaFactorResponse {
            success: output.success,
        })
        .map(Response::from)
}

#[debug_handler]
pub async fn setup_totp(
    State(state): State<AppState>,
    claims: Claims,
    AppJson(payload): AppJson<SetupTotpRequest>,
) -> impl IntoResponse {
    state
        .auth
        .profile
        .setup_totp(SetupTotpInput {
            user_id: claims.sub,
            friendly_name: payload.friendly_name,
        })
        .await
        .map(|output| SetupTotpResponse {
            factor_id: output.factor_id,
            secret: output.secret,
            qr_code_image: output.qr_code_image,
        })
        .map(Response::from)
}

#[debug_handler]
pub async fn verify_totp(
    State(state): State<AppState>,
    claims: Claims,
    AppPath(factor_id): AppPath<i64>,
    AppJson(req): AppJson<VerifyTotpRequest>,
) -> impl IntoResponse {
    state
        .auth
        .profile
        .verify_totp(VerifyTotpInput {
            user_id: claims.sub,
            factor_id,
            code: req.code,
        })
        .await
        .map(|output| VerifyTotpResponse {
            success: output.success,
        })
        .map(Response::from)
}
