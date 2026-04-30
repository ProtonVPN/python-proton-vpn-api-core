// -----------------------------------------------------------------------------
// Copyright (c) 2025 Proton AG
//
// This file is part of ProtonVPN.
//
// ProtonVPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ProtonVPN is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
// -----------------------------------------------------------------------------
//! WireGuard configuration parsing utilities.
//!
//! Parses WireGuard INI-style configuration files to extract keys,
//! addresses, and peer information.

use super::error::*;
use base64::prelude::*;

#[derive(Debug, serde::Serialize, serde::Deserialize, Default, Clone)]
pub struct WireguardConfig {
    #[serde(rename = "Interface")]
    pub interface: WireguardInterface,
    #[serde(rename = "Peer")]
    pub peer: WireguardPeer,
}

impl TryFrom<&str> for WireguardConfig {
    type Error = Error;
    fn try_from(conf: &str) -> Result<Self> {
        let wireguard_conf: WireguardConfig = serini::from_str(conf)?;
        Ok(wireguard_conf)
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default, Clone)]
pub struct WireguardInterface {
    #[serde(rename = "PrivateKey")]
    private_key: String,
    #[serde(rename = "Address")]
    address: String,
    #[serde(rename = "DNS")]
    dns: String,
}

impl WireguardInterface {
    pub fn get_private_key(&self) -> Result<[u8; 32]> {
        let private_key: [u8; 32] = BASE64_STANDARD
            .decode(self.private_key.as_bytes())?
            .as_slice()
            .try_into()?;

        Ok(private_key)
    }

    pub fn get_address_and_prefix(&self) -> Result<(std::net::IpAddr, u8)> {
        match self.address.split_once('/') {
            Some((address_str, prefix)) => {
                Ok((address_str.parse()?, prefix.parse()?))
            }
            None => Err(Error::IO(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid address format",
            ))),
        }
    }

    pub fn get_dns_servers(&self) -> Vec<std::net::IpAddr> {
        self.dns
            .split(',')
            .filter_map(|ip_str| ip_str.parse().ok())
            .collect()
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default, Clone)]
pub struct WireguardPeer {
    #[serde(rename = "PublicKey")]
    public_key: String,
    #[serde(rename = "AllowedIPs")]
    allowed_ips: String,
    #[serde(rename = "Endpoint")]
    endpoint: String,
}

impl WireguardPeer {
    pub fn get_public_key(&self) -> Result<[u8; 32]> {
        let public_key: [u8; 32] = BASE64_STANDARD
            .decode(self.public_key.as_bytes())?
            .as_slice()
            .try_into()?;

        Ok(public_key)
    }

    pub fn get_endpoint(&self) -> Result<std::net::SocketAddr> {
        self.endpoint.parse().map_err(|e| {
            Error::IO(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid endpoint address: {}", e),
            ))
        })
    }
}
