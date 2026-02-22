use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};

use subseq_auth::prelude::AuthenticatedUser;

use crate::api::{AppError, X402App, authorize};
use crate::db;
use crate::models::{PaymentAuditApi, PaymentAuditListQuery, RequireRole};

async fn list_audit_handler<S>(
    State(app): State<S>,
    auth_user: AuthenticatedUser,
    Query(query): Query<PaymentAuditListQuery>,
) -> Result<Json<Vec<PaymentAuditApi>>, AppError>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    let pool = app.pool();
    authorize(pool.as_ref(), &auth_user, RequireRole::Read).await?;
    let rows = db::list_payment_audit(pool.as_ref(), &query).await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

pub fn routes<S>() -> Router<S>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    tracing::info!("Registering route /x402/audit [GET]");
    Router::new().route("/x402/audit", get(list_audit_handler::<S>))
}
