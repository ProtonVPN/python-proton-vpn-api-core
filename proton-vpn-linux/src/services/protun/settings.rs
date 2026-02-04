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

//! Everything for obtaining the settings for a VPN connection from the
//! NetworkManager connection settings.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use base64::prelude::*;
use std::collections::HashMap;
use zbus::zvariant::OwnedValue;

use crate::proton;

pub type ConnectionSettingsSection = HashMap<String, OwnedValue>;
pub type ConnectionSettings = HashMap<String, ConnectionSettingsSection>;

/// Default TUN interface name prefix if connection name is not available
const DEFAULT_TUN_PREFIX: &str = "protun";

#[derive(Debug, Clone)]
pub struct InterfaceParams {
    pub name: String,
    pub address: std::net::IpAddr,
    pub prefix: u32,
}

#[derive(Debug, Clone)]
pub struct ConnectionParams {
    pub interface: InterfaceParams,
    pub dns: Vec<std::net::IpAddr>,
    pub wg_config: proton::vpn::wireguard_utils::WireguardConfig,
    pub peers: Vec<protun::api::connection::PeerInfo>,
}

/// Peer entry in the vpn.data.peers JSON array
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct PeerInfo {
    /// Peer identifier
    pub id: String,
    /// Server endpoint as "IP:port"
    pub endpoint: String,
    /// Base64-encoded server public key
    pub public_key: String,
}

impl TryFrom<PeerInfo> for protun::api::connection::PeerInfo {
    type Error = proton::vpn::Error;

    fn try_from(peer: PeerInfo) -> proton::vpn::Result<Self> {
        let endpoint: SocketAddr = peer.endpoint.parse()?;

        let public_key: [u8; 32] = BASE64_STANDARD
            .decode(peer.public_key.as_bytes())?
            .as_slice()
            .try_into()?;

        Ok(Self {
            peer_id: peer.id.clone(),
            server_ip: protun::api::connection::IpAddress(IpAddr::V4(
                match endpoint.ip() {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(_) => {
                        return Err(proton::vpn::Error::InvalidState(
                            "IPv6 endpoint not supported".into(),
                        ))
                    }
                },
            )),
            server_public_key: protun::api::connection::WgPeerPublicKey(
                public_key,
            ),
            udp_ports: vec![endpoint.port()],
            tcp_ports: vec![],
            tls_ports: vec![],
            priority: 0,
        })
    }
}

/// Take a value from a settings section, converting to the requested type.
/// This takes ownership of the value, avoiding clones.
trait TakeValue {
    fn take_value<T>(&mut self, key: &str) -> proton::vpn::Result<T>
    where
        T: TryFrom<OwnedValue>;
}

impl TakeValue for ConnectionSettingsSection {
    fn take_value<T>(&mut self, key: &str) -> proton::vpn::Result<T>
    where
        T: TryFrom<OwnedValue>,
    {
        let value = self
            .remove(key)
            .ok_or_else(|| proton::vpn::Error::MissingSetting(key.into()))?;
        value.try_into().map_err(|_| {
            proton::vpn::Error::ValueError(format!("Failed to convert {}", key))
        })
    }
}

trait GetSection {
    fn get_section(
        &mut self,
        key: &str,
    ) -> proton::vpn::Result<&mut ConnectionSettingsSection>;
}

impl GetSection for HashMap<String, ConnectionSettingsSection> {
    fn get_section(
        &mut self,
        key: &str,
    ) -> proton::vpn::Result<&mut ConnectionSettingsSection> {
        self.get_mut(key)
            .ok_or_else(|| proton::vpn::Error::MissingSetting(key.into()))
    }
}

/// Extract IPv4 configuration (address, prefix, DNS) from ipv4 settings
fn extract_ipv4_config(
    ipv4: &mut ConnectionSettingsSection,
) -> proton::vpn::Result<(IpAddr, u32, Vec<IpAddr>)> {
    // TODO: LT: Look into address-data, as addresses is deprecated.
    let mut addr_array = ipv4
        .take_value::<Vec<Vec<u32>>>("addresses")?
        .into_iter()
        .map(|v| -> proton::vpn::Result<(u32, u32)> {
            let array = TryInto::<[u32; 3]>::try_into(v).map_err(|_| {
                proton::vpn::Error::ValueError("Invalid addresses entry".into())
            })?;
            Ok((array[0], array[1]))
        });

    let (addr_u32, prefix) = addr_array.next().ok_or_else(|| {
        proton::vpn::Error::MissingSetting("ipv4.addresses[0]".into())
    })??;

    // Address is in network byte order
    let ip = IpAddr::V4(std::net::Ipv4Addr::from_bits(addr_u32));

    // dns is au - array of u32 in network byte order
    let dns_servers: Vec<IpAddr> = ipv4
        .take_value::<Vec<u32>>("dns")?
        .into_iter()
        .map(|ip| IpAddr::V4(std::net::Ipv4Addr::from_bits(ip)))
        .collect();

    Ok((ip, prefix, dns_servers))
}

/// Get the path to the WireGuard config file.
/// Currently finds it relative to the executable (dev/debug mode).
fn get_config_path() -> PathBuf {
    let exe_path =
        std::env::current_exe().expect("Failed to get current exe path"); // nosemgrep - TODO LT: Remove this before shipping to beta
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

/// Load connection parameters from NM settings directly.
///
/// Reads public fields (endpoint, public key, address, DNS) from the "vpn" section
/// of the settings. Private key is still read from the config file.
///
/// Expected "vpn" section keys:
/// - "endpoint": Server endpoint as "IP:port" (required)
/// - "server-public-key": Base64-encoded server public key (required)
/// - "local-address": Client VPN address (optional, defaults to 10.2.0.2)
/// - "prefix": Address prefix length (optional, defaults based on IP version)
/// - "dns": Comma-separated DNS servers (optional, defaults to 10.2.0.1)
pub fn load_connection_params_from_settings(
    mut settings: ConnectionSettings,
) -> proton::vpn::Result<ConnectionParams> {
    // Get interface name (read-only, before we consume settings)
    let interface_name = get_interface_name(&settings)
        .map(|name| sanitize_interface_name(&name))
        .unwrap_or_else(|| DEFAULT_TUN_PREFIX.to_string());

    // Extract WireGuard settings from NM connection settings
    let vpn = settings.get_section("vpn")?;
    let mut data: ConnectionSettingsSection = vpn.take_value("data")?;
    let (internal_address, internal_prefix, dns) =
        extract_ipv4_config(settings.get_section("ipv4")?)?;

    // Parse peers JSON array from vpn.data
    // nmcli escapes commas as \, so we need to unescape them
    let peers_json = data.take_value::<String>("peers")?.replace(r"\,", ",");

    // Deserialize peers with implicit conversion to protun PeerInfo.
    let peers = serde_json::from_str::<Vec<PeerInfo>>(&peers_json)?
        .into_iter()
        .map(|peer| peer.try_into())
        .collect::<Result<Vec<protun::api::connection::PeerInfo>, _>>()?;

    // Still read private key from config file for now
    let config_path = get_config_path();
    let wg_config = proton::vpn::wireguard_utils::WireguardConfig::try_from(
        std::fs::read_to_string(&config_path)?.as_str(),
    )?;

    Ok(ConnectionParams {
        interface: InterfaceParams {
            name: interface_name,
            address: internal_address,
            prefix: internal_prefix,
        },
        peers,
        wg_config,
        dns,
    })
}

/// Helper to extract the interface name from NM connection settings (read-only)
fn get_interface_name(settings: &ConnectionSettings) -> Option<String> {
    let conn = settings.get("connection")?;
    conn.get("interface-name")
        .or_else(|| conn.get("id"))
        .and_then(|v| v.clone().try_into().ok())
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
