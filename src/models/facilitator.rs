use std::collections::HashMap;

use anyhow::anyhow;
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{LibError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FacilitatorProfileApi {
    pub id: Uuid,
    pub name: String,
    pub verify_url: String,
    pub settle_url: String,
    pub supported_url: String,
    pub default_headers: HashMap<String, String>,
    pub timeout_ms: i32,
    pub supported_cache_ttl_secs: i32,
    pub enabled: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct FacilitatorProfileDb {
    pub id: Uuid,
    pub name: String,
    pub verify_url: String,
    pub settle_url: String,
    pub supported_url: String,
    pub default_headers: HashMap<String, String>,
    pub timeout_ms: i32,
    pub supported_cache_ttl_secs: i32,
    pub enabled: bool,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

impl From<FacilitatorProfileDb> for FacilitatorProfileApi {
    fn from(value: FacilitatorProfileDb) -> Self {
        Self {
            id: value.id,
            name: value.name,
            verify_url: value.verify_url,
            settle_url: value.settle_url,
            supported_url: value.supported_url,
            default_headers: value.default_headers,
            timeout_ms: value.timeout_ms,
            supported_cache_ttl_secs: value.supported_cache_ttl_secs,
            enabled: value.enabled,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateFacilitatorProfileRequest {
    pub name: String,
    pub verify_url: String,
    pub settle_url: String,
    pub supported_url: String,
    #[serde(default)]
    pub default_headers: HashMap<String, String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: i32,
    #[serde(default = "default_supported_cache_ttl")]
    pub supported_cache_ttl_secs: i32,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateFacilitatorProfileRequest {
    pub name: Option<String>,
    pub verify_url: Option<String>,
    pub settle_url: Option<String>,
    pub supported_url: Option<String>,
    pub default_headers: Option<HashMap<String, String>>,
    pub timeout_ms: Option<i32>,
    pub supported_cache_ttl_secs: Option<i32>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct CreateFacilitatorProfileDb {
    pub name: String,
    pub verify_url: String,
    pub settle_url: String,
    pub supported_url: String,
    pub default_headers: HashMap<String, String>,
    pub timeout_ms: i32,
    pub supported_cache_ttl_secs: i32,
    pub enabled: bool,
}

#[derive(Debug, Clone, Default)]
pub struct UpdateFacilitatorProfileDb {
    pub name: Option<String>,
    pub verify_url: Option<String>,
    pub settle_url: Option<String>,
    pub supported_url: Option<String>,
    pub default_headers: Option<HashMap<String, String>>,
    pub timeout_ms: Option<i32>,
    pub supported_cache_ttl_secs: Option<i32>,
    pub enabled: Option<bool>,
}

impl TryFrom<CreateFacilitatorProfileRequest> for CreateFacilitatorProfileDb {
    type Error = LibError;

    fn try_from(value: CreateFacilitatorProfileRequest) -> Result<Self> {
        let name = normalize_name(&value.name)?;
        let verify_url = normalize_url(&value.verify_url, "verifyUrl")?;
        let settle_url = normalize_url(&value.settle_url, "settleUrl")?;
        let supported_url = normalize_url(&value.supported_url, "supportedUrl")?;
        let timeout_ms = normalize_timeout_ms(value.timeout_ms)?;
        let supported_cache_ttl_secs =
            normalize_supported_cache_ttl(value.supported_cache_ttl_secs)?;

        Ok(Self {
            name,
            verify_url,
            settle_url,
            supported_url,
            default_headers: value.default_headers,
            timeout_ms,
            supported_cache_ttl_secs,
            enabled: value.enabled,
        })
    }
}

impl TryFrom<UpdateFacilitatorProfileRequest> for UpdateFacilitatorProfileDb {
    type Error = LibError;

    fn try_from(value: UpdateFacilitatorProfileRequest) -> Result<Self> {
        Ok(Self {
            name: value.name.map(|x| normalize_name(&x)).transpose()?,
            verify_url: value
                .verify_url
                .map(|x| normalize_url(&x, "verifyUrl"))
                .transpose()?,
            settle_url: value
                .settle_url
                .map(|x| normalize_url(&x, "settleUrl"))
                .transpose()?,
            supported_url: value
                .supported_url
                .map(|x| normalize_url(&x, "supportedUrl"))
                .transpose()?,
            default_headers: value.default_headers,
            timeout_ms: value.timeout_ms.map(normalize_timeout_ms).transpose()?,
            supported_cache_ttl_secs: value
                .supported_cache_ttl_secs
                .map(normalize_supported_cache_ttl)
                .transpose()?,
            enabled: value.enabled,
        })
    }
}

const fn default_timeout_ms() -> i32 {
    5_000
}

const fn default_supported_cache_ttl() -> i32 {
    600
}

const fn default_true() -> bool {
    true
}

fn normalize_name(name: &str) -> Result<String> {
    let value = name.trim();
    if value.is_empty() {
        return Err(LibError::invalid(
            "Facilitator profile name is required",
            anyhow!("profile name cannot be empty"),
        ));
    }
    Ok(value.to_string())
}

fn normalize_url(url: &str, field: &str) -> Result<String> {
    let value = url.trim();
    if value.is_empty() {
        return Err(LibError::invalid(
            "Facilitator endpoint URL is required",
            anyhow!("{field} cannot be empty"),
        ));
    }
    if !value.starts_with("http://") && !value.starts_with("https://") {
        return Err(LibError::invalid(
            "Facilitator endpoint URL must be absolute",
            anyhow!("{field} must start with http:// or https://"),
        ));
    }
    Ok(value.to_string())
}

fn normalize_timeout_ms(timeout_ms: i32) -> Result<i32> {
    if timeout_ms <= 0 {
        return Err(LibError::invalid(
            "timeoutMs must be greater than zero",
            anyhow!("timeoutMs cannot be <= 0"),
        ));
    }
    Ok(timeout_ms)
}

fn normalize_supported_cache_ttl(value: i32) -> Result<i32> {
    if value < 0 {
        return Err(LibError::invalid(
            "supportedCacheTtlSecs cannot be negative",
            anyhow!("supportedCacheTtlSecs cannot be < 0"),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{CreateFacilitatorProfileDb, CreateFacilitatorProfileRequest};

    #[test]
    fn create_profile_validates_urls() {
        let request = CreateFacilitatorProfileRequest {
            name: "default".to_string(),
            verify_url: "https://example.com/verify".to_string(),
            settle_url: "https://example.com/settle".to_string(),
            supported_url: "https://example.com/supported".to_string(),
            default_headers: Default::default(),
            timeout_ms: 5000,
            supported_cache_ttl_secs: 600,
            enabled: true,
        };

        let db = CreateFacilitatorProfileDb::try_from(request).expect("profile converts");
        assert_eq!(db.name, "default");
    }
}
