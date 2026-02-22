use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use reqwest::Client;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use subseq_auth::prelude::AuthenticatedUser;

use crate::api::{AppError, X402App, authorize};
use crate::db;
use crate::error::{LibError, Result};
use crate::models::{
    CreateFacilitatorProfileDb, CreateFacilitatorProfileRequest, FacilitatorProfileApi,
    RequireRole, UpdateFacilitatorProfileDb, UpdateFacilitatorProfileRequest,
};

pub(crate) async fn verify_payment(
    profile: &FacilitatorProfileApi,
    request: &x402_types::proto::VerifyRequest,
) -> Result<x402_types::proto::v2::VerifyResponse> {
    let value: serde_json::Value =
        post_json(profile, &profile.verify_url, request.as_str()).await?;
    let response = x402_types::proto::VerifyResponse(value);
    response.try_into().map_err(|err| {
        LibError::upstream(
            "ACP verify response was invalid",
            anyhow::anyhow!("verify_payment decode failed: {err}"),
        )
    })
}

pub(crate) async fn settle_payment(
    profile: &FacilitatorProfileApi,
    request: &x402_types::proto::SettleRequest,
) -> Result<x402_types::proto::v2::SettleResponse> {
    let value: serde_json::Value =
        post_json(profile, &profile.settle_url, request.as_str()).await?;
    let response = x402_types::proto::SettleResponse(value);
    serde_json::from_value(response.0).map_err(|err| {
        LibError::upstream(
            "ACP settle response was invalid",
            anyhow::anyhow!("settle_payment decode failed: {err}"),
        )
    })
}

#[allow(dead_code)]
pub(crate) async fn fetch_supported(
    profile: &FacilitatorProfileApi,
) -> Result<x402_types::proto::SupportedResponse> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_millis(profile.timeout_ms as u64))
        .build()
        .map_err(|err| {
            LibError::upstream(
                "Failed to create ACP client",
                anyhow::anyhow!("fetch_supported client build failed: {err}"),
            )
        })?;

    let mut req = client.get(&profile.supported_url);
    for (name, value) in &profile.default_headers {
        req = req.header(name, value);
    }

    let response = req.send().await.map_err(|err| {
        LibError::upstream(
            "Failed to call ACP supported endpoint",
            anyhow::anyhow!("fetch_supported request failed: {err}"),
        )
    })?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(LibError::upstream(
            "ACP supported endpoint returned an error",
            anyhow::anyhow!("fetch_supported status={status} body={body}"),
        ));
    }

    response.json().await.map_err(|err| {
        LibError::upstream(
            "Failed to decode ACP supported response",
            anyhow::anyhow!("fetch_supported decode failed: {err}"),
        )
    })
}

async fn post_json<T: DeserializeOwned>(
    profile: &FacilitatorProfileApi,
    url: &str,
    body_json: &str,
) -> Result<T> {
    let client = Client::builder()
        .timeout(std::time::Duration::from_millis(profile.timeout_ms as u64))
        .build()
        .map_err(|err| {
            LibError::upstream(
                "Failed to create ACP client",
                anyhow::anyhow!("post_json client build failed: {err}"),
            )
        })?;

    let mut req = client
        .post(url)
        .header("content-type", "application/json")
        .body(body_json.to_string());

    for (name, value) in &profile.default_headers {
        req = req.header(name, value);
    }

    let response = req.send().await.map_err(|err| {
        LibError::upstream(
            "Failed to call ACP endpoint",
            anyhow::anyhow!("post_json request failed: {err}"),
        )
    })?;

    let status = response.status();
    if !status.is_success()
        && status != StatusCode::BAD_REQUEST
        && status != StatusCode::PRECONDITION_FAILED
    {
        let body = response.text().await.unwrap_or_default();
        return Err(LibError::upstream(
            "ACP endpoint returned an error",
            anyhow::anyhow!("post_json status={status} body={body}"),
        ));
    }

    response.json().await.map_err(|err| {
        LibError::upstream(
            "Failed to decode ACP response body",
            anyhow::anyhow!("post_json decode failed: {err}"),
        )
    })
}

async fn list_facilitators_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
) -> Result<Json<Vec<FacilitatorProfileApi>>, AppError>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    authorize(pool.as_ref(), &auth_user, RequireRole::Read).await?;
    let rows = db::list_facilitator_profiles(pool.as_ref()).await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn create_facilitator_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<CreateFacilitatorProfileRequest>,
) -> Result<(StatusCode, Json<FacilitatorProfileApi>), AppError>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    authorize(pool.as_ref(), &auth_user, RequireRole::Write).await?;
    let payload: CreateFacilitatorProfileDb = payload.try_into()?;
    let row = db::create_facilitator_profile(pool.as_ref(), payload).await?;
    Ok((StatusCode::CREATED, Json(row.into())))
}

async fn get_facilitator_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<FacilitatorProfileApi>, AppError>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    authorize(pool.as_ref(), &auth_user, RequireRole::Read).await?;
    let row = db::get_facilitator_profile(pool.as_ref(), id)
        .await?
        .ok_or_else(|| {
            LibError::not_found(
                "Facilitator profile not found",
                anyhow::anyhow!("facilitator profile {id} not found"),
            )
        })?;
    Ok(Json(row.into()))
}

async fn update_facilitator_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateFacilitatorProfileRequest>,
) -> Result<Json<FacilitatorProfileApi>, AppError>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    authorize(pool.as_ref(), &auth_user, RequireRole::Write).await?;
    let patch: UpdateFacilitatorProfileDb = payload.try_into()?;
    let row = db::update_facilitator_profile(pool.as_ref(), id, patch)
        .await?
        .ok_or_else(|| {
            LibError::not_found(
                "Facilitator profile not found",
                anyhow::anyhow!("facilitator profile {id} not found"),
            )
        })?;
    Ok(Json(row.into()))
}

async fn delete_facilitator_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    authorize(pool.as_ref(), &auth_user, RequireRole::Write).await?;
    let deleted = db::delete_facilitator_profile(pool.as_ref(), id).await?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError(LibError::not_found(
            "Facilitator profile not found",
            anyhow::anyhow!("facilitator profile {id} not found"),
        )))
    }
}

pub fn routes<S>() -> Router<S>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    tracing::info!("Registering route /x402/facilitator [GET,POST]");
    tracing::info!("Registering route /x402/facilitator/{{id}} [GET,PUT,DELETE]");

    Router::new()
        .route(
            "/x402/facilitator",
            get(list_facilitators_handler::<S>).post(create_facilitator_handler::<S>),
        )
        .route(
            "/x402/facilitator/{id}",
            get(get_facilitator_handler::<S>)
                .put(update_facilitator_handler::<S>)
                .delete(delete_facilitator_handler::<S>),
        )
}
