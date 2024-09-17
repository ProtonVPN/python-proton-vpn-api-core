// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use serde::{Deserialize, Serialize};
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AgentFeatures {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netshield_level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub randomized_nat: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split_tcp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_forwarding: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jail: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bouncing: Option<String>,
}
