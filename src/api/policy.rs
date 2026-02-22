use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use uuid::Uuid;

use subseq_auth::prelude::AuthenticatedUser;

use crate::api::{AppError, X402App, authorize};
use crate::db;
use crate::models::{
    CreateRoutePolicyDb, CreateRoutePolicyRequest, RequireRole, RoutePolicyApi,
    RoutePolicyListQuery, UpdateRoutePolicyDb, UpdateRoutePolicyRequest,
};

async fn list_policies_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Query(query): Query<RoutePolicyListQuery>,
) -> Result<Json<Vec<RoutePolicyApi>>, AppError>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    authorize(pool.as_ref(), &auth_user, RequireRole::Read).await?;
    let rows = db::list_route_policies(pool.as_ref(), &query).await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn create_policy_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Json(payload): Json<CreateRoutePolicyRequest>,
) -> Result<(StatusCode, Json<RoutePolicyApi>), AppError>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    authorize(pool.as_ref(), &auth_user, RequireRole::Write).await?;
    let payload: CreateRoutePolicyDb = payload.try_into()?;
    let row = db::create_route_policy(pool.as_ref(), payload).await?;
    Ok((StatusCode::CREATED, Json(row.into())))
}

async fn get_policy_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<RoutePolicyApi>, AppError>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    authorize(pool.as_ref(), &auth_user, RequireRole::Read).await?;
    let row = db::get_route_policy(pool.as_ref(), id)
        .await?
        .ok_or_else(|| {
            crate::error::LibError::not_found(
                "Route policy not found",
                anyhow::anyhow!("route policy {id} not found"),
            )
        })?;
    Ok(Json(row.into()))
}

async fn update_policy_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateRoutePolicyRequest>,
) -> Result<Json<RoutePolicyApi>, AppError>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    authorize(pool.as_ref(), &auth_user, RequireRole::Write).await?;
    let patch: UpdateRoutePolicyDb = payload.try_into()?;
    let row = db::update_route_policy(pool.as_ref(), id, patch)
        .await?
        .ok_or_else(|| {
            crate::error::LibError::not_found(
                "Route policy not found",
                anyhow::anyhow!("route policy {id} not found"),
            )
        })?;
    Ok(Json(row.into()))
}

async fn delete_policy_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    authorize(pool.as_ref(), &auth_user, RequireRole::Write).await?;
    let deleted = db::delete_route_policy(pool.as_ref(), id).await?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError(crate::error::LibError::not_found(
            "Route policy not found",
            anyhow::anyhow!("route policy {id} not found"),
        )))
    }
}

pub fn routes<S>() -> Router<S>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    tracing::info!("Registering route /x402/policy [GET,POST]");
    tracing::info!("Registering route /x402/policy/{{id}} [GET,PUT,DELETE]");

    Router::new()
        .route(
            "/x402/policy",
            get(list_policies_handler::<S>).post(create_policy_handler::<S>),
        )
        .route(
            "/x402/policy/{id}",
            get(get_policy_handler::<S>)
                .put(update_policy_handler::<S>)
                .delete(delete_policy_handler::<S>),
        )
}
