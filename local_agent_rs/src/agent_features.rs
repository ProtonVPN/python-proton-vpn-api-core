// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use serde::{Deserialize, Serialize};
// -----------------------------------------------------------------------------

#[derive(Default)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
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
    pub forwarded_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jail: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bouncing: Option<String>,
}
