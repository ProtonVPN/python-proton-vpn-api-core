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

    pub fn get_addresses_and_prefix(
        &self,
    ) -> Result<((std::net::IpAddr, u8), Option<(std::net::IpAddr, u8)>)> {
        let mut ipv4 = None;
        let mut ipv6 = None;

        for s in self.address.split(',') {
            let Some((addr_str, prefix_str)) = s.trim().split_once('/') else { continue };
            let Ok(ip) = addr_str.parse::<std::net::IpAddr>() else { continue };
            let Ok(prefix) = prefix_str.trim().parse() else { continue };
            match ip {
                std::net::IpAddr::V4(_) if ipv4.is_none() => ipv4 = Some((ip, prefix)),
                std::net::IpAddr::V6(_) if ipv6.is_none() => ipv6 = Some((ip, prefix)),
                _ => {}
            }
        }

        let ipv4 = ipv4.ok_or_else(|| Error::IO(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "No IPv4 address found",
        )))?;

        Ok((ipv4, ipv6))
    }

    pub fn get_dns_servers(&self) -> Vec<std::net::IpAddr> {
        self.dns
            .split(',')
            .filter_map(|ip_str| ip_str.trim().parse().ok())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_interface(address: &str) -> WireguardInterface {
        WireguardInterface {
            private_key: String::new(),
            address: address.to_string(),
            dns: String::new(),
        }
    }

    #[test]
    fn test_ipv4_and_ipv6() {
        let iface = make_interface("10.0.0.1/24, fd00::1/128");
        let ((ip4, prefix4), ipv6) = iface.get_addresses_and_prefix().unwrap();
        assert_eq!(ip4, "10.0.0.1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(prefix4, 24);
        let (ip6, prefix6) = ipv6.unwrap();
        assert_eq!(ip6, "fd00::1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(prefix6, 128);
    }

    #[test]
    fn test_ipv6_only_returns_error() {
        let iface = make_interface("fd00::1/128");
        assert!(iface.get_addresses_and_prefix().is_err());
    }

    #[test]
    fn test_whitespace_around_commas_is_trimmed() {
        let iface = make_interface("  10.0.0.1/24  ,  fd00::1/128  ");
        assert!(iface.get_addresses_and_prefix().is_ok());
    }

    #[test]
    fn test_malformed_entry_is_skipped() {
        let iface = make_interface("not-an-addr, 10.0.0.1/24");
        let ((ip, _), _) = iface.get_addresses_and_prefix().unwrap();
        assert_eq!(ip, "10.0.0.1".parse::<std::net::IpAddr>().unwrap());
    }

    #[test]
    fn test_entry_without_prefix_is_skipped() {
        let iface = make_interface("10.0.0.1, 192.168.1.1/16");
        let ((ip, prefix), _) = iface.get_addresses_and_prefix().unwrap();
        assert_eq!(ip, "192.168.1.1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(prefix, 16);
    }

    #[test]
    fn test_first_ipv4_wins() {
        let iface = make_interface("10.0.0.1/24, 10.0.0.2/24");
        let ((ip, _), _) = iface.get_addresses_and_prefix().unwrap();
        assert_eq!(ip, "10.0.0.1".parse::<std::net::IpAddr>().unwrap());
    }

    #[test]
    fn test_empty_string_returns_error() {
        let iface = make_interface("");
        assert!(iface.get_addresses_and_prefix().is_err());
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
