use super::profile_model::GetProfileResponse;
use crate::app::extractors::{AppJson, AppPath};
use crate::app::response::Response;
use crate::app::state::AppState;
use crate::auth::domain::profile::{
    DeleteConnectionInput, DeleteMfaFactorInput, ListConnectionInput, ListMfaFactorInput, SetupTotpInput,
    VerifyTotpInput,
};
use crate::auth::inbound::profile_model::{
    ChangePasswordResponse, ConnectionResponse, DeleteConnectionResponse, DeleteMfaFactorResponse,
    MfaFactorResponse, SetupTotpRequest, SetupTotpResponse, UpdateProfileRequest, UpdateProfileResponse,
    VerifyTotpRequest, VerifyTotpResponse,
};
use crate::{app::jwt::Claims, auth::inbound::profile_model::ChangePasswordRequest};
use axum::{Json, debug_handler, extract::Multipart, extract::State, response::IntoResponse};

#[debug_handler]
pub async fn get_profile(State(state): State<AppState>, claims: Claims) -> impl IntoResponse {
    state
        .auth
        .profile
        .get_profile(claims.into())
        .await
        .map(GetProfileResponse::from)
        .map(Response::new)
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
        .update_profile((claims, req).into())
        .await
        .map(UpdateProfileResponse::from)
        .map(Response::new)
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
        .change_password((claims, req).into())
        .await
        .map(ChangePasswordResponse::from)
        .map(Response::new)
}

#[debug_handler]
pub async fn list_connections(State(state): State<AppState>, claims: Claims) -> impl IntoResponse {
    state
        .auth
        .profile
        .list_connections(ListConnectionInput { user_id: claims.sub })
        .await
        .map(|conns| {
            conns
                .into_iter()
                .map(ConnectionResponse::from)
                .collect::<Vec<_>>()
        })
        .map(Response::new)
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
        .map(DeleteConnectionResponse::from)
        .map(Response::new)
}

#[debug_handler]
pub async fn list_mfa_factors(State(state): State<AppState>, claims: Claims) -> impl IntoResponse {
    state
        .auth
        .profile
        .list_mfa_factors(ListMfaFactorInput { user_id: claims.sub })
        .await
        .map(|factors| {
            factors
                .into_iter()
                .map(MfaFactorResponse::from)
                .collect::<Vec<_>>()
        })
        .map(Response::new)
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
        .map(DeleteMfaFactorResponse::from)
        .map(Response::new)
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
            issuer: claims.iss,
        })
        .await
        .map(SetupTotpResponse::from)
        .map(Response::new)
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
        .map(VerifyTotpResponse::from)
        .map(Response::new)
}
