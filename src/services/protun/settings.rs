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

use std::net::IpAddr;

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
    pub address: IpAddr,
    pub prefix: u32,
}

#[derive(Debug, Clone)]
pub struct ConnectionParams {
    pub interface: InterfaceParams,
    pub dns: Vec<IpAddr>,
    pub private_key: [u8; 32],
    pub peers: Vec<protun::api::connection::PeerInfo>,
}

/// Peer entry in the vpn.data.peers JSON array
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
struct PeerInfo {
    /// Peer identifier
    pub id: String,
    /// Server endpoint ip address
    pub endpoint: String,
    /// Base64-encoded server public key
    pub public_key: String,
    /// udp ports to connect on
    pub udp_ports: Vec<u16>,
    /// tcp ports to connect on
    pub tcp_ports: Vec<u16>,
    /// tls ports to connect on
    pub tls_ports: Vec<u16>,
    /// Peer priority
    pub priority: i32,
}

impl TryFrom<PeerInfo> for protun::api::connection::PeerInfo {
    type Error = proton::vpn::Error;

    fn try_from(peer: PeerInfo) -> proton::vpn::Result<Self> {
        let server_ip: IpAddr = peer.endpoint.parse()?;

        let public_key: [u8; 32] = BASE64_STANDARD
            .decode(peer.public_key.as_bytes())?
            .as_slice()
            .try_into()?;

        // Double check the address is not ipv6 address
        if let IpAddr::V6(address) = &server_ip {
            return Err(proton::vpn::Error::InvalidState(
                format!("IPv6 endpoint not supported {address}"),
            ))
        };

        Ok(Self {
            peer_id: peer.id,
            server_ip: protun::api::connection::IpAddress(server_ip),
            server_public_key: protun::api::connection::WgPeerPublicKey(
                public_key,
            ),
            udp_ports: peer.udp_ports,
            tcp_ports: peer.tcp_ports,
            tls_ports: peer.tls_ports,
            priority: peer.priority,
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

/// Load connection parameters from NM settings directly.
///
/// Reads public fields (endpoint, public key, address, DNS) from the "vpn" section
/// and private key from "vpn.secrets" section.
///
/// Expected "vpn.data" keys:
/// - "peers": JSON array of peer objects with id, endpoint, public-key
///
/// Expected "vpn.secrets" keys:
/// - "private-key": Base64-encoded WireGuard private key
///
/// Expected "ipv4" keys:
/// - "addresses": Array of [address, prefix, gateway]
/// - "dns": Array of DNS server addresses
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
    let mut secrets: ConnectionSettingsSection = vpn.take_value("secrets")?;
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

    // Get private key from vpn.secrets section
    let private_key = get_private_key_from_secrets(&mut secrets)?;

    Ok(ConnectionParams {
        interface: InterfaceParams {
            name: interface_name,
            address: internal_address,
            prefix: internal_prefix,
        },
        peers,
        private_key,
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

/// Extract the WireGuard private key from the vpn.secrets section.
///
/// The private key is expected to be base64-encoded in the "private-key" field
/// of the "vpn.secrets" section.
pub fn get_private_key_from_secrets(
    secrets: &mut ConnectionSettingsSection,
) -> proton::vpn::Result<[u8; 32]> {

    let private_key_bytes : [u8;32] = BASE64_STANDARD
        .decode(secrets.take_value::<String>("private-key")?.as_bytes())
        .map_err(|e| {
            proton::vpn::Error::ValueError(format!("Failed to decode private key: {}", e))
        })?.try_into().map_err(|_| {
            proton::vpn::Error::ValueError("Private key must be 32 bytes".into())
        })?;

    private_key_bytes.as_slice().try_into().map_err(|_| {
        proton::vpn::Error::ValueError("Private key must be 32 bytes".into())
    })
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

pub fn needs_secrets(
    mut settings: ConnectionSettings,
) -> proton::vpn::Result<bool> {
    let vpn = settings.get_section("vpn")?;
    let secrets: ConnectionSettingsSection = vpn.take_value("secrets")?;
    Ok(!secrets.contains_key("private-key"))
}