use anyhow::anyhow;
use sqlx::{FromRow, PgPool, QueryBuilder};
use uuid::Uuid;

use crate::error::{LibError, Result};
use crate::models::{
    CreatePaymentAudit, PaymentAuditChannel, PaymentAuditDb, PaymentAuditListQuery,
    PaymentAuditResult,
};

#[derive(Debug, Clone, FromRow)]
struct PaymentAuditRow {
    id: Uuid,
    request_id: String,
    route_policy_id: Option<Uuid>,
    method: String,
    path: String,
    channel: String,
    result: String,
    status_code: i32,
    payer: Option<String>,
    api_key_id: Option<Uuid>,
    api_key_name: Option<String>,
    details: serde_json::Value,
    created_at: chrono::NaiveDateTime,
}

fn channel_to_str(channel: PaymentAuditChannel) -> &'static str {
    match channel {
        PaymentAuditChannel::X402 => "x402",
        PaymentAuditChannel::ApiKey => "api_key",
    }
}

fn result_to_str(result: PaymentAuditResult) -> &'static str {
    match result {
        PaymentAuditResult::Pass => "pass",
        PaymentAuditResult::Fail => "fail",
        PaymentAuditResult::Challenge => "challenge",
    }
}

fn parse_channel(value: &str) -> Result<PaymentAuditChannel> {
    match value {
        "x402" => Ok(PaymentAuditChannel::X402),
        "api_key" => Ok(PaymentAuditChannel::ApiKey),
        _ => Err(LibError::database(
            "Failed to decode payment audit channel",
            anyhow!("unknown payment audit channel: {value}"),
        )),
    }
}

fn parse_result(value: &str) -> Result<PaymentAuditResult> {
    match value {
        "pass" => Ok(PaymentAuditResult::Pass),
        "fail" => Ok(PaymentAuditResult::Fail),
        "challenge" => Ok(PaymentAuditResult::Challenge),
        _ => Err(LibError::database(
            "Failed to decode payment audit result",
            anyhow!("unknown payment audit result: {value}"),
        )),
    }
}

fn row_to_model(row: PaymentAuditRow) -> Result<PaymentAuditDb> {
    Ok(PaymentAuditDb {
        id: row.id,
        request_id: row.request_id,
        route_policy_id: row.route_policy_id,
        method: row.method,
        path: row.path,
        channel: parse_channel(&row.channel)?,
        result: parse_result(&row.result)?,
        status_code: row.status_code,
        payer: row.payer,
        api_key_id: row.api_key_id,
        api_key_name: row.api_key_name,
        details: row.details,
        created_at: row.created_at,
    })
}

pub async fn create_payment_audit(pool: &PgPool, payload: &CreatePaymentAudit) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO x402.payment_audit (
            request_id,
            route_policy_id,
            method,
            path,
            channel,
            result,
            status_code,
            payer,
            api_key_id,
            api_key_name,
            details
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(&payload.request_id)
    .bind(payload.route_policy_id)
    .bind(&payload.method)
    .bind(&payload.path)
    .bind(channel_to_str(payload.channel))
    .bind(result_to_str(payload.result))
    .bind(payload.status_code)
    .bind(&payload.payer)
    .bind(payload.api_key_id)
    .bind(&payload.api_key_name)
    .bind(&payload.details)
    .execute(pool)
    .await
    .map_err(|err| {
        LibError::database(
            "Failed to write payment audit",
            anyhow!("create_payment_audit failed: {err}"),
        )
    })?;

    Ok(())
}

pub async fn list_payment_audit(
    pool: &PgPool,
    query: &PaymentAuditListQuery,
) -> Result<Vec<PaymentAuditDb>> {
    let (page, limit) = query.pagination();
    let offset: i64 = ((page - 1) as i64) * (limit as i64);

    let mut qb = QueryBuilder::new(
        r#"
        SELECT
            id,
            request_id,
            route_policy_id,
            method,
            path,
            channel,
            result,
            status_code,
            payer,
            api_key_id,
            api_key_name,
            details,
            created_at
        FROM x402.payment_audit
        "#,
    );

    let mut has_where = false;
    if let Some(channel) = query.channel {
        qb.push(if has_where { " AND " } else { " WHERE " });
        has_where = true;
        qb.push("channel = ").push_bind(channel_to_str(channel));
    }
    if let Some(result) = query.result {
        qb.push(if has_where { " AND " } else { " WHERE " });
        has_where = true;
        qb.push("result = ").push_bind(result_to_str(result));
    }
    if let Some(request_id) = query.request_id.as_ref() {
        qb.push(if has_where { " AND " } else { " WHERE " });
        qb.push("request_id = ").push_bind(request_id);
    }

    qb.push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(limit as i64)
        .push(" OFFSET ")
        .push_bind(offset);

    let rows = qb
        .build_query_as::<PaymentAuditRow>()
        .fetch_all(pool)
        .await
        .map_err(|err| {
            LibError::database(
                "Failed to list payment audit",
                anyhow!("list_payment_audit failed: {err}"),
            )
        })?;

    rows.into_iter().map(row_to_model).collect()
}
