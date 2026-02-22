use anyhow::anyhow;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::error::{LibError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthChannel {
    X402,
    ApiKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    AnyOf,
    AllOf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402RequirementApi {
    pub scheme: String,
    pub network: String,
    pub amount: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    pub asset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct X402RequirementDb {
    pub scheme: String,
    pub network: String,
    pub amount: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    pub asset: String,
    pub extra: Option<Value>,
}

impl From<X402RequirementApi> for X402RequirementDb {
    fn from(value: X402RequirementApi) -> Self {
        Self {
            scheme: value.scheme,
            network: value.network,
            amount: value.amount,
            pay_to: value.pay_to,
            max_timeout_seconds: value.max_timeout_seconds,
            asset: value.asset,
            extra: value.extra,
        }
    }
}

impl From<X402RequirementDb> for X402RequirementApi {
    fn from(value: X402RequirementDb) -> Self {
        Self {
            scheme: value.scheme,
            network: value.network,
            amount: value.amount,
            pay_to: value.pay_to,
            max_timeout_seconds: value.max_timeout_seconds,
            asset: value.asset,
            extra: value.extra,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutePolicyApi {
    pub id: Uuid,
    pub method: String,
    pub path_pattern: String,
    pub mode: AuthMode,
    pub channels: Vec<AuthChannel>,
    pub facilitator_profile_id: Option<Uuid>,
    pub x402_accepts: Vec<X402RequirementApi>,
    pub active: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct RoutePolicyDb {
    pub id: Uuid,
    pub method: String,
    pub path_pattern: String,
    pub mode: AuthMode,
    pub channels: Vec<AuthChannel>,
    pub facilitator_profile_id: Option<Uuid>,
    pub x402_accepts: Vec<X402RequirementDb>,
    pub active: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl From<RoutePolicyDb> for RoutePolicyApi {
    fn from(value: RoutePolicyDb) -> Self {
        Self {
            id: value.id,
            method: value.method,
            path_pattern: value.path_pattern,
            mode: value.mode,
            channels: value.channels,
            facilitator_profile_id: value.facilitator_profile_id,
            x402_accepts: value.x402_accepts.into_iter().map(Into::into).collect(),
            active: value.active,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRoutePolicyRequest {
    pub method: String,
    pub path_pattern: String,
    pub mode: AuthMode,
    pub channels: Vec<AuthChannel>,
    pub facilitator_profile_id: Option<Uuid>,
    #[serde(default)]
    pub x402_accepts: Vec<X402RequirementApi>,
    #[serde(default = "default_true")]
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRoutePolicyRequest {
    pub mode: Option<AuthMode>,
    pub channels: Option<Vec<AuthChannel>>,
    pub facilitator_profile_id: Option<Option<Uuid>>,
    pub x402_accepts: Option<Vec<X402RequirementApi>>,
    pub active: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct CreateRoutePolicyDb {
    pub method: String,
    pub path_pattern: String,
    pub mode: AuthMode,
    pub channels: Vec<AuthChannel>,
    pub facilitator_profile_id: Option<Uuid>,
    pub x402_accepts: Vec<X402RequirementDb>,
    pub active: bool,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateRoutePolicyDb {
    pub mode: Option<AuthMode>,
    pub channels: Option<Vec<AuthChannel>>,
    pub facilitator_profile_id: Option<Option<Uuid>>,
    pub x402_accepts: Option<Vec<X402RequirementDb>>,
    pub active: Option<bool>,
}

impl TryFrom<CreateRoutePolicyRequest> for CreateRoutePolicyDb {
    type Error = LibError;

    fn try_from(value: CreateRoutePolicyRequest) -> Result<Self> {
        let method = normalize_http_method(&value.method)?;
        let path_pattern = normalize_path_pattern(&value.path_pattern)?;
        let channels = normalize_channels(value.channels)?;

        Ok(Self {
            method,
            path_pattern,
            mode: value.mode,
            channels,
            facilitator_profile_id: value.facilitator_profile_id,
            x402_accepts: value.x402_accepts.into_iter().map(Into::into).collect(),
            active: value.active,
        })
    }
}

impl TryFrom<UpdateRoutePolicyRequest> for UpdateRoutePolicyDb {
    type Error = LibError;

    fn try_from(value: UpdateRoutePolicyRequest) -> Result<Self> {
        let channels = match value.channels {
            Some(channels) => Some(normalize_channels(channels)?),
            None => None,
        };

        Ok(Self {
            mode: value.mode,
            channels,
            facilitator_profile_id: value.facilitator_profile_id,
            x402_accepts: value
                .x402_accepts
                .map(|items| items.into_iter().map(Into::into).collect()),
            active: value.active,
        })
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutePolicyListQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
    pub method: Option<String>,
    pub active: Option<bool>,
}

impl RoutePolicyListQuery {
    pub fn pagination(&self) -> (u32, u32) {
        let page = self.page.unwrap_or(1).max(1);
        let limit = self.limit.unwrap_or(50).clamp(1, 200);
        (page, limit)
    }
}

const fn default_true() -> bool {
    true
}

pub fn normalize_http_method(method: &str) -> Result<String> {
    let normalized = method.trim().to_ascii_uppercase();
    if normalized.is_empty() {
        return Err(LibError::invalid(
            "HTTP method is required",
            anyhow!("route policy method cannot be empty"),
        ));
    }
    Ok(normalized)
}

pub fn normalize_path_pattern(path_pattern: &str) -> Result<String> {
    let normalized = path_pattern.trim();
    if !normalized.starts_with('/') {
        return Err(LibError::invalid(
            "Path pattern must start with '/'",
            anyhow!("invalid route policy path pattern: {normalized}"),
        ));
    }
    Ok(normalized.to_string())
}

pub fn normalize_channels(channels: Vec<AuthChannel>) -> Result<Vec<AuthChannel>> {
    let mut out = Vec::with_capacity(channels.len());
    for channel in channels {
        if !out.contains(&channel) {
            out.push(channel);
        }
    }

    if out.is_empty() {
        return Err(LibError::invalid(
            "At least one auth channel is required",
            anyhow!("route policy channels cannot be empty"),
        ));
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        AuthChannel, AuthMode, CreateRoutePolicyRequest, UpdateRoutePolicyRequest,
        normalize_channels,
    };

    #[test]
    fn normalize_channels_dedupes_order() {
        let out = normalize_channels(vec![
            AuthChannel::X402,
            AuthChannel::ApiKey,
            AuthChannel::X402,
        ])
        .expect("normalize channels");
        assert_eq!(out, vec![AuthChannel::X402, AuthChannel::ApiKey]);
    }

    #[test]
    fn create_policy_normalizes_method_and_path() {
        let input = CreateRoutePolicyRequest {
            method: "post".to_string(),
            path_pattern: "/mcp/test".to_string(),
            mode: AuthMode::AnyOf,
            channels: vec![AuthChannel::X402],
            facilitator_profile_id: None,
            x402_accepts: vec![],
            active: true,
        };

        let out = super::CreateRoutePolicyDb::try_from(input).expect("convert");
        assert_eq!(out.method, "POST");
        assert_eq!(out.path_pattern, "/mcp/test");
    }

    #[test]
    fn update_policy_converts_channel_patch() {
        let input = UpdateRoutePolicyRequest {
            mode: Some(AuthMode::AllOf),
            channels: Some(vec![AuthChannel::ApiKey, AuthChannel::ApiKey]),
            facilitator_profile_id: None,
            x402_accepts: None,
            active: Some(false),
        };

        let out = super::UpdateRoutePolicyDb::try_from(input).expect("convert");
        assert_eq!(out.channels.expect("channels"), vec![AuthChannel::ApiKey]);
    }
}
