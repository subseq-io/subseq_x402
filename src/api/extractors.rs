use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::models::X402AuthContext;

#[derive(Debug, Clone)]
pub struct RequireX402(pub X402AuthContext);

#[derive(Debug, Clone)]
pub struct RequireApiKey(pub X402AuthContext);

#[derive(Debug, Clone)]
pub struct RequireX402OrApiKey(pub X402AuthContext);

#[derive(Debug, Clone)]
pub struct RequireX402AndApiKey(pub X402AuthContext);

impl<S> FromRequestParts<S> for RequireX402
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let context = parts
            .extensions
            .get::<X402AuthContext>()
            .cloned()
            .ok_or_else(|| payment_required("x402 proof is required"))?;

        if context.has_x402() {
            Ok(Self(context))
        } else {
            Err(payment_required("x402 proof is required"))
        }
    }
}

impl<S> FromRequestParts<S> for RequireApiKey
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let context = parts
            .extensions
            .get::<X402AuthContext>()
            .cloned()
            .ok_or_else(|| unauthorized("api key proof is required"))?;

        if context.has_api_key() {
            Ok(Self(context))
        } else {
            Err(unauthorized("api key proof is required"))
        }
    }
}

impl<S> FromRequestParts<S> for RequireX402OrApiKey
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let context = parts
            .extensions
            .get::<X402AuthContext>()
            .cloned()
            .ok_or_else(|| unauthorized("x402 or api key proof is required"))?;

        if context.has_x402() || context.has_api_key() {
            Ok(Self(context))
        } else {
            Err(unauthorized("x402 or api key proof is required"))
        }
    }
}

impl<S> FromRequestParts<S> for RequireX402AndApiKey
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let context = parts
            .extensions
            .get::<X402AuthContext>()
            .cloned()
            .ok_or_else(|| payment_required("x402 and api key proofs are required"))?;

        if !context.has_x402() {
            return Err(payment_required("x402 proof is required"));
        }
        if !context.has_api_key() {
            return Err(unauthorized("api key proof is required"));
        }

        Ok(Self(context))
    }
}

fn unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({
            "error": {
                "code": "unauthorized",
                "message": message,
            }
        })),
    )
        .into_response()
}

fn payment_required(message: &str) -> Response {
    (
        StatusCode::PAYMENT_REQUIRED,
        axum::Json(json!({
            "error": {
                "code": "payment_required",
                "message": message,
            }
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_flags_work_for_extractors() {
        let mut context = X402AuthContext::new("req".to_string());
        assert!(!context.has_x402());
        assert!(!context.has_api_key());

        context.succeeded_channels.push("x402".to_string());
        context.x402 = Some(crate::models::X402Proof {
            payer: "payer".to_string(),
            network: "eip155:1".to_string(),
            scheme: "exact".to_string(),
            resource: None,
        });
        assert!(context.has_x402());
        assert!(!context.has_api_key());
    }
}
