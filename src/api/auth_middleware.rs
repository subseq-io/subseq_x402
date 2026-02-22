use std::sync::Arc;

use anyhow::anyhow;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use serde_json::json;
use sqlx::PgPool;
use subseq_agents::{ApiKeyStore, ToolActor};
use uuid::Uuid;
use x402_types::proto::v1;
use x402_types::proto::v2;

use crate::api::facilitator::{settle_payment, verify_payment};
use crate::db;
use crate::models::{
    ApiKeyProof, AuthChannel, AuthMode, CreatePaymentAudit, FacilitatorProfileApi,
    PaymentAuditChannel, PaymentAuditResult, RoutePolicyDb, X402AuthContext, X402Proof,
    X402RequirementDb,
};

#[derive(Clone)]
pub struct X402AuthLayerConfig {
    pub pool: Arc<PgPool>,
    pub api_key_store: Arc<dyn ApiKeyStore>,
    pub api_key_mount_name: String,
    pub request_id_header: String,
    pub default_resource_description: String,
    pub default_resource_mime_type: String,
}

pub type X402AuthMiddlewareState = X402AuthLayerConfig;

impl X402AuthLayerConfig {
    pub fn new(pool: Arc<PgPool>, api_key_store: Arc<dyn ApiKeyStore>) -> Self {
        Self {
            pool,
            api_key_store,
            api_key_mount_name: "default".to_string(),
            request_id_header: "x-request-id".to_string(),
            default_resource_description: "x402 protected resource".to_string(),
            default_resource_mime_type: "application/json".to_string(),
        }
    }

    pub fn with_api_key_mount_name(mut self, mount_name: impl Into<String>) -> Self {
        self.api_key_mount_name = mount_name.into();
        self
    }
}

pub async fn x402_auth_middleware(
    State(config): State<X402AuthLayerConfig>,
    mut request: Request,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_string();
    let request_id = resolve_request_id(request.headers(), &config.request_id_header);

    let policy = match db::resolve_route_policy(config.pool.as_ref(), &method, &path).await {
        Ok(policy) => policy,
        Err(err) => {
            tracing::error!(error = %err, "failed to resolve x402 route policy");
            return internal_error_response();
        }
    };

    let Some(policy) = policy else {
        return next.run(request).await;
    };

    let mut auth_context = X402AuthContext::new(request_id.clone());
    auth_context.route_policy_id = Some(policy.id);
    auth_context.mode = Some(policy.mode);

    let mut first_failure: Option<AuthFailure> = None;
    let mut any_passed = false;
    let mut all_passed = true;

    for channel in &policy.channels {
        let headers = request.headers().clone();
        let eval = match channel {
            AuthChannel::X402 => eval_x402_channel(&config, &policy, &headers).await,
            AuthChannel::ApiKey => eval_api_key_channel(&config, &headers).await,
        };

        match eval {
            Ok(ChannelSuccess::X402(proof)) => {
                any_passed = true;
                auth_context.succeeded_channels.push("x402".to_string());
                auth_context.x402 = Some(proof.clone());
                write_audit(
                    &config,
                    &CreatePaymentAudit {
                        request_id: request_id.clone(),
                        route_policy_id: Some(policy.id),
                        method: method.clone(),
                        path: path.clone(),
                        channel: PaymentAuditChannel::X402,
                        result: PaymentAuditResult::Pass,
                        status_code: StatusCode::OK.as_u16() as i32,
                        payer: Some(proof.payer),
                        api_key_id: None,
                        api_key_name: None,
                        details: json!({"mode": "pass"}),
                    },
                )
                .await;
            }
            Ok(ChannelSuccess::ApiKey(proof)) => {
                any_passed = true;
                auth_context.succeeded_channels.push("api_key".to_string());
                auth_context.api_key = Some(proof.clone());
                write_audit(
                    &config,
                    &CreatePaymentAudit {
                        request_id: request_id.clone(),
                        route_policy_id: Some(policy.id),
                        method: method.clone(),
                        path: path.clone(),
                        channel: PaymentAuditChannel::ApiKey,
                        result: PaymentAuditResult::Pass,
                        status_code: StatusCode::OK.as_u16() as i32,
                        payer: None,
                        api_key_id: Some(proof.api_key_id),
                        api_key_name: Some(proof.api_key_name),
                        details: json!({"mode": "pass"}),
                    },
                )
                .await;
            }
            Err(failure) => {
                all_passed = false;
                if first_failure.is_none() {
                    first_failure = Some(failure.clone());
                }

                let (audit_channel, audit_result, status_code, details) = failure.audit_values();
                write_audit(
                    &config,
                    &CreatePaymentAudit {
                        request_id: request_id.clone(),
                        route_policy_id: Some(policy.id),
                        method: method.clone(),
                        path: path.clone(),
                        channel: audit_channel,
                        result: audit_result,
                        status_code,
                        payer: None,
                        api_key_id: None,
                        api_key_name: None,
                        details,
                    },
                )
                .await;

                if policy.mode == AuthMode::AllOf {
                    continue;
                }
            }
        }

        if policy.mode == AuthMode::AnyOf && any_passed {
            request.extensions_mut().insert(auth_context);
            return next.run(request).await;
        }
    }

    match policy.mode {
        AuthMode::AnyOf => {
            if any_passed {
                request.extensions_mut().insert(auth_context);
                next.run(request).await
            } else {
                failure_response(first_failure, &config, &policy, &request)
            }
        }
        AuthMode::AllOf => {
            if all_passed {
                request.extensions_mut().insert(auth_context);
                next.run(request).await
            } else {
                failure_response(first_failure, &config, &policy, &request)
            }
        }
    }
}

#[derive(Debug, Clone)]
enum ChannelSuccess {
    X402(X402Proof),
    ApiKey(ApiKeyProof),
}

#[derive(Debug, Clone)]
enum AuthFailure {
    X402Challenge { message: String },
    ApiKeyUnauthorized { message: String },
    Internal { message: String },
}

impl AuthFailure {
    fn audit_values(
        &self,
    ) -> (
        PaymentAuditChannel,
        PaymentAuditResult,
        i32,
        serde_json::Value,
    ) {
        match self {
            Self::X402Challenge { message } => (
                PaymentAuditChannel::X402,
                PaymentAuditResult::Challenge,
                StatusCode::PAYMENT_REQUIRED.as_u16() as i32,
                json!({"error": message}),
            ),
            Self::ApiKeyUnauthorized { message } => (
                PaymentAuditChannel::ApiKey,
                PaymentAuditResult::Fail,
                StatusCode::UNAUTHORIZED.as_u16() as i32,
                json!({"error": message}),
            ),
            Self::Internal { message } => (
                PaymentAuditChannel::X402,
                PaymentAuditResult::Fail,
                StatusCode::INTERNAL_SERVER_ERROR.as_u16() as i32,
                json!({"error": message}),
            ),
        }
    }
}

async fn eval_x402_channel(
    config: &X402AuthLayerConfig,
    policy: &RoutePolicyDb,
    headers: &HeaderMap,
) -> std::result::Result<ChannelSuccess, AuthFailure> {
    let signature = payment_signature(headers)
        .map(ToString::to_string)
        .ok_or_else(|| AuthFailure::X402Challenge {
            message: "Missing Payment-Signature header".to_string(),
        })?;

    let payload = decode_payment_payload(&signature).map_err(|err| AuthFailure::X402Challenge {
        message: format!("Invalid payment payload: {err}"),
    })?;

    let accepted =
        parse_policy_accepts(&policy.x402_accepts).map_err(|err| AuthFailure::Internal {
            message: err.to_string(),
        })?;

    if !accepted
        .iter()
        .any(|candidate| candidate == &payload.accepted)
    {
        return Err(AuthFailure::X402Challenge {
            message: "Accepted payment requirements do not match route policy".to_string(),
        });
    }

    let profile = load_profile(config, policy).await?;

    let verify_request = v2::VerifyRequest {
        x402_version: v2::X402Version2,
        payment_payload: payload.clone(),
        payment_requirements: payload.accepted.clone(),
    };
    let verify_request =
        x402_types::proto::VerifyRequest::try_from(&verify_request).map_err(|err| {
            AuthFailure::Internal {
                message: format!("Failed to build verify request: {err}"),
            }
        })?;

    let verify = verify_payment(&profile, &verify_request)
        .await
        .map_err(|err| AuthFailure::X402Challenge {
            message: err.public.into_owned(),
        })?;

    let payer = match verify {
        v1::VerifyResponse::Valid { payer } => payer,
        v1::VerifyResponse::Invalid { reason, .. } => {
            return Err(AuthFailure::X402Challenge {
                message: format!("Payment verification failed: {reason}"),
            });
        }
    };

    let settle = settle_payment(&profile, &verify_request)
        .await
        .map_err(|err| AuthFailure::X402Challenge {
            message: err.public.into_owned(),
        })?;

    match settle {
        v1::SettleResponse::Success { .. } => {}
        v1::SettleResponse::Error { reason, .. } => {
            return Err(AuthFailure::X402Challenge {
                message: format!("Payment settlement failed: {reason}"),
            });
        }
    }

    Ok(ChannelSuccess::X402(X402Proof {
        payer,
        network: payload.accepted.network.to_string(),
        scheme: payload.accepted.scheme,
        resource: payload.resource.map(|r| r.url),
    }))
}

async fn eval_api_key_channel(
    config: &X402AuthLayerConfig,
    headers: &HeaderMap,
) -> std::result::Result<ChannelSuccess, AuthFailure> {
    let Some(key) = extract_api_key(headers).map(ToString::to_string) else {
        return Err(AuthFailure::ApiKeyUnauthorized {
            message: "Missing API key".to_string(),
        });
    };

    let actor = config
        .api_key_store
        .authenticate_key(&config.api_key_mount_name, &key)
        .await
        .map_err(|err| AuthFailure::Internal {
            message: format!("api key auth failed: {err}"),
        })?
        .ok_or_else(|| AuthFailure::ApiKeyUnauthorized {
            message: "Invalid API key".to_string(),
        })?;

    Ok(ChannelSuccess::ApiKey(api_actor_to_proof(actor)))
}

async fn load_profile(
    config: &X402AuthLayerConfig,
    policy: &RoutePolicyDb,
) -> std::result::Result<FacilitatorProfileApi, AuthFailure> {
    let profile_id = policy
        .facilitator_profile_id
        .ok_or_else(|| AuthFailure::X402Challenge {
            message: "Route policy is missing facilitator profile".to_string(),
        })?;

    let profile = db::get_facilitator_profile(config.pool.as_ref(), profile_id)
        .await
        .map_err(|err| AuthFailure::Internal {
            message: format!("failed to load facilitator profile: {err}"),
        })?
        .ok_or_else(|| AuthFailure::X402Challenge {
            message: "Configured facilitator profile was not found".to_string(),
        })?;

    let profile: FacilitatorProfileApi = profile.into();
    if !profile.enabled {
        return Err(AuthFailure::X402Challenge {
            message: "Configured facilitator profile is disabled".to_string(),
        });
    }

    Ok(profile)
}

fn payment_signature(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Payment-Signature")
        .or_else(|| headers.get("payment-signature"))
        .and_then(header_to_trimmed)
}

fn header_to_trimmed(value: &HeaderValue) -> Option<&str> {
    let raw = value.to_str().ok()?.trim();
    if raw.is_empty() { None } else { Some(raw) }
}

fn decode_payment_payload(
    signature: &str,
) -> std::result::Result<
    v2::PaymentPayload<v2::PaymentRequirements, serde_json::Value>,
    anyhow::Error,
> {
    let bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .or_else(|_| URL_SAFE.decode(signature))?;
    let payload = serde_json::from_slice::<
        v2::PaymentPayload<v2::PaymentRequirements, serde_json::Value>,
    >(&bytes)?;
    Ok(payload)
}

fn parse_policy_accepts(
    accepts: &[X402RequirementDb],
) -> std::result::Result<Vec<v2::PaymentRequirements>, anyhow::Error> {
    accepts
        .iter()
        .map(|item| {
            let network = item.network.parse().map_err(|err| {
                anyhow!(
                    "invalid payment requirement network '{}': {}",
                    item.network,
                    err
                )
            })?;
            Ok(v2::PaymentRequirements {
                scheme: item.scheme.clone(),
                network,
                amount: item.amount.clone(),
                pay_to: item.pay_to.clone(),
                max_timeout_seconds: item.max_timeout_seconds,
                asset: item.asset.clone(),
                extra: item.extra.clone(),
            })
        })
        .collect()
}

fn extract_api_key(headers: &HeaderMap) -> Option<&str> {
    if let Some(value) = headers.get("x-api-key").and_then(header_to_trimmed) {
        return Some(value);
    }

    let auth = headers.get("authorization").and_then(header_to_trimmed)?;
    auth.strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|x| !x.is_empty())
}

fn api_actor_to_proof(actor: ToolActor) -> ApiKeyProof {
    ApiKeyProof {
        api_key_id: actor.api_key_id,
        api_key_name: actor.api_key_name,
        actor_user_id: actor.user_id.0,
        mount_name: actor.mcp_mount_name,
    }
}

fn failure_response(
    failure: Option<AuthFailure>,
    config: &X402AuthLayerConfig,
    policy: &RoutePolicyDb,
    request: &Request,
) -> Response {
    match failure {
        Some(AuthFailure::X402Challenge { message }) => {
            payment_required_response(config, policy, request, &message)
        }
        Some(AuthFailure::ApiKeyUnauthorized { message }) => unauthorized_response(&message),
        Some(AuthFailure::Internal { .. }) | None => internal_error_response(),
    }
}

fn unauthorized_response(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        JsonBody::new("unauthorized", message),
    )
        .into_response()
}

fn internal_error_response() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        JsonBody::new("internal_error", "Internal server error"),
    )
        .into_response()
}

fn payment_required_response(
    config: &X402AuthLayerConfig,
    policy: &RoutePolicyDb,
    request: &Request,
    message: &str,
) -> Response {
    let accepts = parse_policy_accepts(&policy.x402_accepts).unwrap_or_default();
    let resource = v2::ResourceInfo {
        description: config.default_resource_description.clone(),
        mime_type: config.default_resource_mime_type.clone(),
        url: infer_resource_url(request),
    };
    let required = v2::PaymentRequired {
        x402_version: v2::X402Version2,
        error: Some(message.to_string()),
        resource,
        accepts,
    };

    let encoded_header = match serde_json::to_vec(&required) {
        Ok(bytes) => URL_SAFE_NO_PAD.encode(bytes),
        Err(err) => {
            tracing::error!(error = %err, "failed to encode payment required payload");
            String::new()
        }
    };

    let mut response = (
        StatusCode::PAYMENT_REQUIRED,
        JsonBody::new("payment_required", message),
    )
        .into_response();

    if !encoded_header.is_empty() {
        if let Ok(value) = HeaderValue::from_str(&encoded_header) {
            response.headers_mut().insert("Payment-Required", value);
        }
    }

    response
}

fn infer_resource_url(request: &Request) -> String {
    let host = request
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    format!("http://{}{}", host, request.uri())
}

async fn write_audit(config: &X402AuthLayerConfig, payload: &CreatePaymentAudit) {
    if let Err(err) = db::create_payment_audit(config.pool.as_ref(), payload).await {
        tracing::error!(error = %err, "failed to write x402 payment audit row");
    }
}

fn resolve_request_id(headers: &HeaderMap, request_id_header: &str) -> String {
    headers
        .get(request_id_header)
        .and_then(|header| header.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

struct JsonBody {
    code: &'static str,
    message: String,
}

impl JsonBody {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl IntoResponse for JsonBody {
    fn into_response(self) -> Response {
        axum::Json(json!({
            "error": {
                "code": self.code,
                "message": self.message,
            }
        }))
        .into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::http::{HeaderMap, HeaderValue};

    use super::extract_api_key;
    use crate::db::policy::path_pattern_matches;
    use crate::models::{AuthChannel, AuthMode};

    #[test]
    fn api_key_extraction_prefers_x_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("abc"));
        headers.insert("authorization", HeaderValue::from_static("Bearer def"));
        assert_eq!(extract_api_key(&headers), Some("abc"));
    }

    #[test]
    fn policy_ordering_helpers_work() {
        assert!(path_pattern_matches("/mcp/*", "/mcp/foo"));
        assert!(!path_pattern_matches("/mcp/foo", "/mcp/foo/bar"));
    }

    #[test]
    fn auth_mode_semantics_are_explicit() {
        let channels = vec![AuthChannel::X402, AuthChannel::ApiKey];
        let mode = AuthMode::AllOf;
        let mut passed = HashMap::new();
        passed.insert("x402", true);
        passed.insert("api_key", false);

        let ok = match mode {
            AuthMode::AnyOf => channels.iter().any(|channel| {
                passed
                    .get(match channel {
                        AuthChannel::X402 => "x402",
                        AuthChannel::ApiKey => "api_key",
                    })
                    .copied()
                    .unwrap_or(false)
            }),
            AuthMode::AllOf => channels.iter().all(|channel| {
                passed
                    .get(match channel {
                        AuthChannel::X402 => "x402",
                        AuthChannel::ApiKey => "api_key",
                    })
                    .copied()
                    .unwrap_or(false)
            }),
        };

        assert!(!ok);
    }
}
