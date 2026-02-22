use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentAuditChannel {
    X402,
    ApiKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentAuditResult {
    Pass,
    Fail,
    Challenge,
}

#[derive(Debug, Clone)]
pub struct PaymentAuditDb {
    pub id: Uuid,
    pub request_id: String,
    pub route_policy_id: Option<Uuid>,
    pub method: String,
    pub path: String,
    pub channel: PaymentAuditChannel,
    pub result: PaymentAuditResult,
    pub status_code: i32,
    pub payer: Option<String>,
    pub api_key_id: Option<Uuid>,
    pub api_key_name: Option<String>,
    pub details: Value,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentAuditApi {
    pub id: Uuid,
    pub request_id: String,
    pub route_policy_id: Option<Uuid>,
    pub method: String,
    pub path: String,
    pub channel: PaymentAuditChannel,
    pub result: PaymentAuditResult,
    pub status_code: i32,
    pub payer: Option<String>,
    pub api_key_id: Option<Uuid>,
    pub api_key_name: Option<String>,
    pub details: Value,
    pub created_at: NaiveDateTime,
}

impl From<PaymentAuditDb> for PaymentAuditApi {
    fn from(value: PaymentAuditDb) -> Self {
        Self {
            id: value.id,
            request_id: value.request_id,
            route_policy_id: value.route_policy_id,
            method: value.method,
            path: value.path,
            channel: value.channel,
            result: value.result,
            status_code: value.status_code,
            payer: value.payer,
            api_key_id: value.api_key_id,
            api_key_name: value.api_key_name,
            details: value.details,
            created_at: value.created_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CreatePaymentAudit {
    pub request_id: String,
    pub route_policy_id: Option<Uuid>,
    pub method: String,
    pub path: String,
    pub channel: PaymentAuditChannel,
    pub result: PaymentAuditResult,
    pub status_code: i32,
    pub payer: Option<String>,
    pub api_key_id: Option<Uuid>,
    pub api_key_name: Option<String>,
    pub details: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentAuditListQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub channel: Option<PaymentAuditChannel>,
    pub result: Option<PaymentAuditResult>,
    pub request_id: Option<String>,
}

impl PaymentAuditListQuery {
    pub fn pagination(&self) -> (u32, u32) {
        let page = self.page.unwrap_or(1).max(1);
        let limit = self.limit.unwrap_or(100).clamp(1, 500);
        (page, limit)
    }
}
