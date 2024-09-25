// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use crate::agent_features::*;
use serde::{Deserialize, Serialize};

/// Represents the state of the connection to the local agent client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Connected,
    HardJailed,
    Disconnected,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Reason {
    pub code: i32,
    #[serde(rename = "final")]
    pub is_final: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnectionDetails {
    pub device_ip: Option<String>,
    pub device_country: Option<String>,
    pub server_ipv4: Option<String>,
    pub server_ipv6: Option<String>,
}

/// Represents the status message from the local agent server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct StatusMessage {
    pub state: State,
    pub reason: Option<Reason>,
    pub features: Option<AgentFeatures>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_details: Option<ConnectionDetails>,
    /*
      "state": "connected",
        "features": {
          "netshield-level": 2,
          "split-tcp": true,
          "bouncing": "0",
          "randomized-nat": false,
          "port-forwarding": false,
          "jail": false,
          "safe-mode": false
        },
        "client-device-ip": "88.170.255.159",
        "connection-details": {
          "device-ip": "88.170.255.159",
          "device-country": "FR",
          "server-ipv4": "185.159.159.16"
        }
    */
}

/// Represents the error message from the local agent server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ErrorMessage {
    pub code: u32,
    pub description: String,
    /*
      {
        "error":{
          "code":86203,
          "description":"session has no fingerprint"
        }
      }
    */
}

/// Represents the response from the local agent server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct StatusGet {}

/// Represents the request to the local agent server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Request {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features_set: Option<AgentFeatures>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_get: Option<StatusGet>,
}
