use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::policy::AuthMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthChannelResult {
    Pass,
    Fail,
    Challenge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402Proof {
    pub payer: String,
    pub network: String,
    pub scheme: String,
    pub resource: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyProof {
    pub api_key_id: Uuid,
    pub api_key_name: String,
    pub actor_user_id: Uuid,
    pub mount_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X402AuthContext {
    pub request_id: String,
    pub route_policy_id: Option<Uuid>,
    pub mode: Option<AuthMode>,
    pub succeeded_channels: Vec<String>,
    pub x402: Option<X402Proof>,
    pub api_key: Option<ApiKeyProof>,
}

impl X402AuthContext {
    pub fn new(request_id: String) -> Self {
        Self {
            request_id,
            route_policy_id: None,
            mode: None,
            succeeded_channels: Vec::new(),
            x402: None,
            api_key: None,
        }
    }

    pub fn has_x402(&self) -> bool {
        self.x402.is_some()
    }

    pub fn has_api_key(&self) -> bool {
        self.api_key.is_some()
    }
}

pub const DEFAULT_ADMIN_ROLE: &str = "x402_admin";
pub const DEFAULT_READ_ROLE: &str = "x402_read";
pub const X402_ROLE_SCOPE: &str = "x402";
pub const X402_ROLE_SCOPE_ID: &str = "global";
