// -----------------------------------------------------------------------------
// Copyright (c) 2026 Proton AG
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

//! Utility functions for the NetworkManager VPN Plugin

use std::collections::HashMap;
use std::path::PathBuf;

use zbus::zvariant::{OwnedValue, Value};

use crate::proton;

use super::types::NMConnectionSettings;

/// Default TUN interface name prefix if connection name is not available
pub const DEFAULT_TUN_PREFIX: &str = "protun";

/// All parameters needed to establish a VPN connection
pub struct ConnectionParams {
    pub interface_name: String,
    pub peer_info: protun::api::connection::PeerInfo,
    pub wg_config: proton::vpn::wireguard_utils::WireguardConfig,
    /// VPN server gateway IP (network byte order)
    pub external_gateway: u32,
    /// Internal VPN address (network byte order)
    pub internal_address: u32,
    pub prefix: u8,
    /// DNS servers (network byte order)
    pub dns: Vec<u32>,
}

/// Get the path to the WireGuard config file.
/// Currently finds it relative to the executable (dev/debug mode).
pub fn get_config_path() -> PathBuf {
    let exe_path =
        std::env::current_exe().expect("Failed to get current exe path");
    exe_path
        .parent()
        .expect("Failed to get debug dir")
        .parent()
        .expect("Failed to get target dir")
        .parent()
        .expect("Failed to get project root")
        .join("configs")
        .join("current.conf")
}

/// Load and parse all connection parameters from NM settings and config file.
pub fn load_connection_params(
    settings: &NMConnectionSettings,
) -> proton::vpn::Result<ConnectionParams> {
    // Get interface name (prefers interface-name, falls back to id)
    let interface_name = get_interface_name(settings)
        .map(|name| sanitize_interface_name(&name))
        .unwrap_or_else(|| DEFAULT_TUN_PREFIX.to_string());

    // Read WireGuard configuration
    let config_path = get_config_path();
    let (peer_info, wg_config) = read_conf(&config_path)?;

    // Extract IP configuration (all converted to network byte order)
    let external_gateway = ipv4_to_network_order(peer_info.server_ip.0)?;
    let (internal_address_ip, prefix) =
        wg_config.interface.get_address_and_prefix()?;
    let internal_address = ipv4_to_network_order(internal_address_ip)?;
    let dns = wg_config
        .interface
        .get_dns_servers()
        .into_iter()
        .map(ipv4_to_network_order)
        .collect::<Result<Vec<u32>, _>>()?;

    Ok(ConnectionParams {
        interface_name,
        peer_info,
        wg_config,
        external_gateway,
        internal_address,
        prefix,
        dns,
    })
}

/// Convert an IPv4 address to network byte order (big-endian) u32.
/// Returns an error for IPv6 addresses.
fn ipv4_to_network_order(ip: std::net::IpAddr) -> proton::vpn::Result<u32> {
    match ip {
        std::net::IpAddr::V4(v4) => Ok(u32::from(v4).to_be()),
        std::net::IpAddr::V6(_) => Err(proton::vpn::Error::InvalidState(
            "IPv6 addresses not yet supported".to_string(),
        )),
    }
}

/// Helper to extract the interface name from NM connection settings
fn get_interface_name(settings: &NMConnectionSettings) -> Option<String> {
    settings.get("connection").and_then(|conn| {
        get_string(conn, "interface-name").or_else(|| get_string(conn, "id"))
    })
}

/// Extract a string value from a D-Bus dictionary section
fn get_string(
    section: &HashMap<String, OwnedValue>,
    key: &str,
) -> Option<String> {
    section.get(key).and_then(|v| {
        let value: &Value = v.downcast_ref().ok()?;
        if let Value::Str(s) = value {
            Some(s.to_string())
        } else {
            None
        }
    })
}

/// Read and parse a WireGuard configuration file
fn read_conf(
    wireguard_conf: &std::path::Path,
) -> proton::vpn::Result<(
    protun::api::connection::PeerInfo,
    proton::vpn::wireguard_utils::WireguardConfig,
)> {
    let conf = proton::vpn::wireguard_utils::WireguardConfig::try_from(
        std::fs::read_to_string(wireguard_conf)?.as_str(),
    )?;

    let peer_id = wireguard_conf
        .file_stem()
        .ok_or_else(|| {
            proton::vpn::Error::IO(std::io::Error::other(
                "Invalid wireguard conf filename",
            ))
        })?
        .to_string_lossy()
        .to_string();

    let endpoint = conf.peer.get_endpoint()?;
    let peer_info = protun::api::connection::PeerInfo {
        peer_id,
        server_ip: protun::api::connection::IpAddress(endpoint.ip()),
        server_public_key: protun::api::connection::WgPeerPublicKey(
            conf.peer.get_public_key()?,
        ),
        udp_ports: vec![endpoint.port()],
        tcp_ports: vec![],
        tls_ports: vec![],
        priority: 0,
    };

    Ok((peer_info, conf))
}

/// Sanitize a connection name to be a valid Linux network interface name.
/// Linux interface names can be at most 15 characters and should only contain
/// alphanumeric characters, hyphens, and underscores.
fn sanitize_interface_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .filter_map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                Some(c.to_ascii_lowercase())
            } else if c == ' ' {
                Some('_')
            } else {
                None
            }
        })
        .take(15) // Linux interface name max length is 15 (IFNAMSIZ - 1)
        .collect();

    if sanitized.is_empty() {
        DEFAULT_TUN_PREFIX.to_string()
    } else {
        sanitized
    }
}

impl From<proton::vpn::Error> for zbus::fdo::Error {
    fn from(err: proton::vpn::Error) -> Self {
        zbus::fdo::Error::Failed(format!("{}", err))
    }
}
