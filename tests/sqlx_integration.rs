use subseq_x402::db;
use subseq_x402::models::{
    AuthChannel, AuthMode, CreateFacilitatorProfileDb, CreatePaymentAudit, CreateRoutePolicyDb,
    PaymentAuditChannel, PaymentAuditListQuery, PaymentAuditResult, RoutePolicyListQuery,
    UpdateFacilitatorProfileDb, UpdateRoutePolicyDb, X402RequirementDb,
};

#[sqlx::test(migrations = "./migrations")]
async fn facilitator_policy_audit_roundtrip(pool: sqlx::PgPool) {
    let facilitator = db::create_facilitator_profile(
        &pool,
        CreateFacilitatorProfileDb {
            name: "default".to_string(),
            verify_url: "https://example.test/verify".to_string(),
            settle_url: "https://example.test/settle".to_string(),
            supported_url: "https://example.test/supported".to_string(),
            default_headers: std::collections::HashMap::new(),
            timeout_ms: 1000,
            supported_cache_ttl_secs: 60,
            enabled: true,
        },
    )
    .await
    .expect("create facilitator profile");

    let fetched = db::get_facilitator_profile(&pool, facilitator.id)
        .await
        .expect("get facilitator profile")
        .expect("facilitator exists");
    assert_eq!(fetched.name, "default");

    let updated = db::update_facilitator_profile(
        &pool,
        facilitator.id,
        UpdateFacilitatorProfileDb {
            timeout_ms: Some(2000),
            ..Default::default()
        },
    )
    .await
    .expect("update facilitator profile")
    .expect("facilitator still exists");
    assert_eq!(updated.timeout_ms, 2000);

    let policy = db::create_route_policy(
        &pool,
        CreateRoutePolicyDb {
            method: "GET".to_string(),
            path_pattern: "/mcp/*".to_string(),
            mode: AuthMode::AnyOf,
            channels: vec![AuthChannel::X402, AuthChannel::ApiKey],
            facilitator_profile_id: Some(facilitator.id),
            x402_accepts: vec![X402RequirementDb {
                scheme: "exact".to_string(),
                network: "eip155:1".to_string(),
                amount: "1000000".to_string(),
                pay_to: "0xrecipient".to_string(),
                max_timeout_seconds: 300,
                asset: "0xasset".to_string(),
                extra: None,
            }],
            active: true,
        },
    )
    .await
    .expect("create route policy");

    let resolved = db::resolve_route_policy(&pool, "GET", "/mcp/tool")
        .await
        .expect("resolve route policy")
        .expect("policy resolves");
    assert_eq!(resolved.id, policy.id);

    let list = db::list_route_policies(&pool, &RoutePolicyListQuery::default())
        .await
        .expect("list route policies");
    assert_eq!(list.len(), 1);

    let updated_policy = db::update_route_policy(
        &pool,
        policy.id,
        UpdateRoutePolicyDb {
            mode: Some(AuthMode::AllOf),
            ..Default::default()
        },
    )
    .await
    .expect("update policy")
    .expect("policy exists");
    assert_eq!(updated_policy.mode, AuthMode::AllOf);

    db::create_payment_audit(
        &pool,
        &CreatePaymentAudit {
            request_id: "req-1".to_string(),
            route_policy_id: Some(policy.id),
            method: "GET".to_string(),
            path: "/mcp/tool".to_string(),
            channel: PaymentAuditChannel::X402,
            result: PaymentAuditResult::Pass,
            status_code: 200,
            payer: Some("0xpayer".to_string()),
            api_key_id: None,
            api_key_name: None,
            details: serde_json::json!({"ok": true}),
        },
    )
    .await
    .expect("create audit");

    let audits = db::list_payment_audit(
        &pool,
        &PaymentAuditListQuery {
            page: None,
            limit: None,
            channel: Some(PaymentAuditChannel::X402),
            result: Some(PaymentAuditResult::Pass),
            request_id: Some("req-1".to_string()),
        },
    )
    .await
    .expect("list audit");
    assert_eq!(audits.len(), 1);

    let deleted_policy = db::delete_route_policy(&pool, policy.id)
        .await
        .expect("delete policy");
    assert!(deleted_policy);

    let deleted_facilitator = db::delete_facilitator_profile(&pool, facilitator.id)
        .await
        .expect("delete facilitator");
    assert!(deleted_facilitator);
}
