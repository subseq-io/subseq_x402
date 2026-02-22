use std::collections::HashMap;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::get;
use axum::{Router, body::Body};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::Request;
use subseq_agents::{ApiKeyStore, InMemoryApiKeyStore};
use subseq_auth::prelude::UserId;
use tower::ServiceExt;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use x402_types::proto::v2;

use subseq_x402::api::X402AuthLayerConfig;
use subseq_x402::api::extractors::{
    RequireApiKey, RequireX402, RequireX402AndApiKey, RequireX402OrApiKey,
};
use subseq_x402::db;
use subseq_x402::models::{
    AuthChannel, AuthMode, CreateFacilitatorProfileDb, CreateRoutePolicyDb, PaymentAuditListQuery,
    X402RequirementDb,
};

#[sqlx::test(migrations = "./migrations")]
async fn middleware_enforces_x402_and_api_key_channels(pool: sqlx::PgPool) {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/verify"))
        .and(header("x-acp-key", "secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "isValid": true,
            "payer": "0xpayer"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/settle"))
        .and(header("x-acp-key", "secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "success": true,
            "payer": "0xpayer",
            "transaction": "0xabc",
            "network": "eip155:1"
        })))
        .mount(&mock_server)
        .await;

    let mut headers = HashMap::new();
    headers.insert("x-acp-key".to_string(), "secret".to_string());

    let profile = db::create_facilitator_profile(
        &pool,
        CreateFacilitatorProfileDb {
            name: "default".to_string(),
            verify_url: format!("{}/verify", mock_server.uri()),
            settle_url: format!("{}/settle", mock_server.uri()),
            supported_url: format!("{}/supported", mock_server.uri()),
            default_headers: headers,
            timeout_ms: 2_000,
            supported_cache_ttl_secs: 60,
            enabled: true,
        },
    )
    .await
    .expect("create facilitator profile");

    let accepts = vec![X402RequirementDb {
        scheme: "exact".to_string(),
        network: "eip155:1".to_string(),
        amount: "1000000".to_string(),
        pay_to: "0xrecipient".to_string(),
        max_timeout_seconds: 300,
        asset: "0xasset".to_string(),
        extra: None,
    }];

    db::create_route_policy(
        &pool,
        CreateRoutePolicyDb {
            method: "GET".to_string(),
            path_pattern: "/mcp/x402".to_string(),
            mode: AuthMode::AnyOf,
            channels: vec![AuthChannel::X402],
            facilitator_profile_id: Some(profile.id),
            x402_accepts: accepts.clone(),
            active: true,
        },
    )
    .await
    .expect("create x402 route policy");

    db::create_route_policy(
        &pool,
        CreateRoutePolicyDb {
            method: "GET".to_string(),
            path_pattern: "/mcp/any".to_string(),
            mode: AuthMode::AnyOf,
            channels: vec![AuthChannel::X402, AuthChannel::ApiKey],
            facilitator_profile_id: Some(profile.id),
            x402_accepts: accepts.clone(),
            active: true,
        },
    )
    .await
    .expect("create any-of route policy");

    db::create_route_policy(
        &pool,
        CreateRoutePolicyDb {
            method: "GET".to_string(),
            path_pattern: "/mcp/all".to_string(),
            mode: AuthMode::AllOf,
            channels: vec![AuthChannel::X402, AuthChannel::ApiKey],
            facilitator_profile_id: Some(profile.id),
            x402_accepts: accepts.clone(),
            active: true,
        },
    )
    .await
    .expect("create all-of route policy");

    let key_store = Arc::new(InMemoryApiKeyStore::new());
    let created_key = key_store
        .create_key(UserId(Uuid::new_v4()), "default", "primary", None)
        .await
        .expect("create API key");

    let base_router = Router::new()
        .route("/mcp/x402", get(x402_handler))
        .route("/mcp/any", get(any_handler))
        .route("/mcp/all", get(all_handler));
    let app = subseq_x402::api::x402_auth_layer(
        base_router,
        X402AuthLayerConfig::new(Arc::new(pool.clone()), key_store.clone()),
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/mcp/x402")
                .method("GET")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(response.headers().contains_key("Payment-Required"));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/mcp/any")
                .method("GET")
                .header("x-api-key", &created_key.plaintext_key)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let signature = payment_signature(accepts[0].clone());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/mcp/all")
                .method("GET")
                .header("Payment-Signature", signature.clone())
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/mcp/all")
                .method("GET")
                .header("Payment-Signature", signature)
                .header("x-api-key", &created_key.plaintext_key)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let audit_rows = db::list_payment_audit(
        &pool,
        &PaymentAuditListQuery {
            page: Some(1),
            limit: Some(100),
            channel: None,
            result: None,
            request_id: None,
        },
    )
    .await
    .expect("list audit rows");
    assert!(audit_rows.len() >= 4);
}

async fn x402_handler(_: RequireX402) -> StatusCode {
    StatusCode::OK
}

async fn any_handler(_: RequireX402OrApiKey) -> StatusCode {
    StatusCode::OK
}

async fn all_handler(_: RequireX402AndApiKey, _: RequireApiKey) -> StatusCode {
    StatusCode::OK
}

fn payment_signature(accept: X402RequirementDb) -> String {
    let payload = v2::PaymentPayload {
        accepted: v2::PaymentRequirements {
            scheme: accept.scheme,
            network: accept.network.parse().expect("chain id"),
            amount: accept.amount,
            pay_to: accept.pay_to,
            max_timeout_seconds: accept.max_timeout_seconds,
            asset: accept.asset,
            extra: accept.extra,
        },
        payload: serde_json::json!({"signature": "sig"}),
        resource: None,
        x402_version: v2::X402Version2,
    };

    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("encode payload"))
}
