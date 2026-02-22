use std::sync::Arc;

use anyhow::anyhow;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::Serialize;
use sqlx::PgPool;
use subseq_agents::ApiKeyStore;
use subseq_auth::prelude::{AuthenticatedUser, UserId, ValidatesIdentity};

use crate::error::{ErrorKind, LibError, Result};
use crate::models::{
    DEFAULT_ADMIN_ROLE, DEFAULT_READ_ROLE, RequireRole, X402_ROLE_SCOPE, X402_ROLE_SCOPE_ID,
};

pub mod audit;
pub mod auth_middleware;
pub mod extractors;
pub mod facilitator;
pub mod health;
pub mod policy;
pub use auth_middleware::X402AuthLayerConfig;

#[derive(Debug)]
pub struct AppError(pub LibError);

impl From<LibError> for AppError {
    fn from(value: LibError) -> Self {
        Self(value)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody {
    code: String,
    message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorEnvelope {
    error: ErrorBody,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self.0.kind {
            ErrorKind::Conflict => StatusCode::CONFLICT,
            ErrorKind::Database => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorKind::Forbidden => StatusCode::FORBIDDEN,
            ErrorKind::InvalidInput => StatusCode::BAD_REQUEST,
            ErrorKind::NotFound => StatusCode::NOT_FOUND,
            ErrorKind::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorKind::Upstream => StatusCode::BAD_GATEWAY,
            ErrorKind::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        };
        tracing::error!(kind = ?self.0.kind, error = %self.0.source, "x402 api request failed");
        (
            status,
            Json(ErrorEnvelope {
                error: ErrorBody {
                    code: self.0.code.into_owned(),
                    message: self.0.public.into_owned(),
                },
            }),
        )
            .into_response()
    }
}

pub trait HasPool {
    fn pool(&self) -> Arc<PgPool>;
}

pub trait HasApiKeyStore {
    fn api_key_store(&self) -> Arc<dyn ApiKeyStore>;
}

pub trait HasIdentity: ValidatesIdentity {}

impl<T> HasIdentity for T where T: ValidatesIdentity {}

pub trait X402App: HasPool + HasApiKeyStore + HasIdentity {}

pub fn routes<S>() -> Router<S>
where
    S: X402App + Clone + Send + Sync + 'static,
{
    Router::new()
        .merge(health::routes::<S>())
        .merge(policy::routes::<S>())
        .merge(facilitator::routes::<S>())
        .merge(audit::routes::<S>())
}

pub fn x402_auth_layer<S>(
    router: Router<S>,
    config: auth_middleware::X402AuthLayerConfig,
) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(axum::middleware::from_fn_with_state::<
        _,
        _,
        (
            axum::extract::State<auth_middleware::X402AuthLayerConfig>,
            axum::extract::Request,
        ),
    >(config, auth_middleware::x402_auth_middleware))
}

pub(crate) async fn authorize(
    pool: &PgPool,
    auth_user: &AuthenticatedUser,
    required: RequireRole,
) -> Result<()> {
    let roles = match required {
        RequireRole::Read => configured_read_roles(),
        RequireRole::Write => configured_write_roles(),
    };

    let user_id = auth_user.id();
    for role in roles {
        let has_role = subseq_auth::db::user_has_effective_access(
            pool,
            user_id,
            X402_ROLE_SCOPE,
            X402_ROLE_SCOPE_ID,
            &role,
        )
        .await
        .map_err(|err| {
            LibError::database(
                "Failed to verify x402 role",
                anyhow!("authorize role lookup failed: {err}"),
            )
        })?;

        if has_role {
            return Ok(());
        }
    }

    Err(LibError::forbidden(
        "You do not have permission to access x402 administration APIs",
        anyhow!("user {} is missing required x402 role", user_id),
    ))
}

pub(crate) fn configured_read_roles() -> Vec<String> {
    let default = format!("{DEFAULT_READ_ROLE},{DEFAULT_ADMIN_ROLE}");
    parse_roles(&std::env::var("X402_READ_ROLES").unwrap_or(default))
}

pub(crate) fn configured_write_roles() -> Vec<String> {
    let default = DEFAULT_ADMIN_ROLE.to_string();
    parse_roles(&std::env::var("X402_WRITE_ROLES").unwrap_or(default))
}

fn parse_roles(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    for item in raw.split(',') {
        let role = item.trim();
        if role.is_empty() {
            continue;
        }
        if !out.iter().any(|existing| existing == role) {
            out.push(role.to_string());
        }
    }
    if out.is_empty() {
        out.push(DEFAULT_ADMIN_ROLE.to_string());
    }
    out
}

#[allow(dead_code)]
fn _assert_user_id_send_sync(_: UserId) {}
