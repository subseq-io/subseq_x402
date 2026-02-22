use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::api::X402App;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    status: &'static str,
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(HealthResponse { status: "ok" }))
}

pub fn routes<S>() -> Router<S>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    tracing::info!("Registering route /x402/healthz [GET]");
    Router::new().route("/x402/healthz", get(health_handler))
}
