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

/// A version number for the expected structure of the settings,
/// for now we just use this to guard against loading settings that are
/// using an outdated format.
pub const VERSION: u32 = 1;

pub const SETTINGS_KEY: &str = "settings";

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PcapFileInfo {
    pub file_path: std::path::PathBuf,
    pub max_bytes: Option<u64>,
    pub mode: FileWriteMode,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileWriteMode {
    Append,
    Overwrite,
}

#[derive(Debug, Clone)]
pub struct InterfaceParams {
    pub name: String,
    pub address: IpAddr,
    pub prefix: u32,
}

impl TryFrom<PcapFileInfo> for protun::api::connection::PcapFileInfo {
    type Error = proton::vpn::Error;

    fn try_from(params: PcapFileInfo) -> Result<Self, Self::Error> {
        Ok(protun::api::connection::PcapFileInfo {
            file: protun::api::connection::PcapFile::Path{
                path: params.file_path.to_str().ok_or_else(|| proton::vpn::Error::InvalidState("Invalid file path".into()))?.to_string(),
                mode: match params.mode {
                    FileWriteMode::Append => protun::api::connection::FileWriteMode::Append,
                    FileWriteMode::Overwrite => protun::api::connection::FileWriteMode::Overwrite,
                },
            },
            max_bytes: params.max_bytes,
        })
    }
}

/// Peer entry in the vpn.data.peers JSON array
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PeerInfo {
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

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Settings {
    pub version : u32,
    pub pcap_file : Option<PcapFileInfo>,
    pub peers: Vec<PeerInfo>,
}

#[derive(Debug, Clone)]
pub struct ConnectionParams {
    pub interface: InterfaceParams,
    pub dns: Vec<IpAddr>,
    pub private_key: [u8; 32],
    pub peers: Vec<protun::api::connection::PeerInfo>,
    pub pcap_file: Option<protun::api::connection::PcapFileInfo>,
}

/// Convert a value to a type that can be stored in NM settings (string, int, array, etc).
/// Any type that implements serde Serialize and Deserialize will be implemented
/// as a ProtunSetting, which can be easily converted to/from a string for storage in NM settings.
pub trait ProtunSetting: Sized {
    fn from_settings_str(s: &str) -> proton::vpn::Result<Self>;
    fn to_settings_string(&self) -> proton::vpn::Result<String>;
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> ProtunSetting for T {
    fn to_settings_string(&self) -> proton::vpn::Result<String> {
        // nmcli does not allow commas in values, so we need to escape them as \.
        // This is fine so long as we are consistent in both directions.
        //
        // So if we're manually creating a nmcli connection we should use
        // nm-protun-service with the cli option, which will produce the
        // nmcli command with the correct escaping.
        //
        // The linux client will do the escaping correctly.
        Ok(serde_json::to_string(self)
            .map_err(|_| proton::vpn::Error::ValueError("Failed to serialize".into()))?
            .replace(",", r"\,"))
    }

    fn from_settings_str(s: &str) -> proton::vpn::Result<Self> {
        Ok(serde_json::from_str::<Self>(&s.replace(r"\,", ","))?)
    }
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
            proton::vpn::Error::ValueError(format!("Failed to convert '{}'", key))
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

pub fn read_json_key<T>(key: &str, data: &mut  ConnectionSettingsSection) -> proton::vpn::Result<T>
where
    T: ProtunSetting,
{
    Ok(T::from_settings_str(&data.take_value::<String>(key)?)?)
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
    mut connection_settings: ConnectionSettings,
) -> proton::vpn::Result<ConnectionParams> {
    // Get interface name (read-only, before we consume settings)
    let interface_name = get_interface_name(&connection_settings)
        .map(|name| sanitize_interface_name(&name))
        .unwrap_or_else(|| DEFAULT_TUN_PREFIX.to_string());

    // Extract WireGuard settings from NM connection settings
    let vpn = connection_settings.get_section("vpn")?;
    let mut data: ConnectionSettingsSection = vpn.take_value("data")?;

    let settings = read_json_key::<Settings>(SETTINGS_KEY, &mut data)?;

    if settings.version != VERSION {
        return Err(proton::vpn::Error::InvalidState(format!(
            "Settings version mismatch: expected {}, got {}",
            VERSION, settings.version
        )));
    }

    let mut secrets: ConnectionSettingsSection = vpn.take_value("secrets")?;
    let (internal_address, internal_prefix, dns) =
        extract_ipv4_config(connection_settings.get_section("ipv4")?)?;

    // Deserialize peers with implicit conversion to protun PeerInfo.
    let peers = settings.peers
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
        pcap_file: settings.pcap_file.map(|file| file.try_into()).transpose()?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;
    use zbus::zvariant::{OwnedValue, Value};

    fn str_owned_value(s: &str) -> OwnedValue {
        OwnedValue::try_from(Value::from(s.to_string())).unwrap()
    }

    // ---- sanitize_interface_name ----

    #[test]
    fn test_sanitize_truncates_at_15_chars() {
        let result = sanitize_interface_name("abcdefghijklmnopqrstuvwxyz");
        assert_eq!(result.len(), 15);
        assert_eq!(result, "abcdefghijklmno");
    }

    #[test]
    fn test_sanitize_converts_spaces_to_underscores() {
        assert_eq!(sanitize_interface_name("my vpn"), "my_vpn");
    }

    #[test]
    fn test_sanitize_removes_special_chars() {
        assert_eq!(sanitize_interface_name("vpn@home!"), "vpnhome");
    }

    #[test]
    fn test_sanitize_empty_returns_default() {
        assert_eq!(sanitize_interface_name(""), DEFAULT_TUN_PREFIX);
    }

    #[test]
    fn test_sanitize_only_special_chars_returns_default() {
        assert_eq!(sanitize_interface_name("!@#$%^"), DEFAULT_TUN_PREFIX);
    }

    #[test]
    fn test_sanitize_lowercases_input() {
        assert_eq!(sanitize_interface_name("MyVPN"), "myvpn");
    }

    #[test]
    fn test_sanitize_preserves_hyphens_and_underscores() {
        assert_eq!(sanitize_interface_name("my-vpn_0"), "my-vpn_0");
    }

    // ---- ProtunSetting comma escaping ----

    fn minimal_settings(tcp_ports: Vec<u16>, tls_ports: Vec<u16>) -> Settings {
        Settings {
            version: VERSION,
            pcap_file: None,
            peers: vec![PeerInfo {
                id: "p1".into(),
                endpoint: "1.2.3.4".into(),
                public_key: BASE64_STANDARD.encode([0u8; 32]),
                udp_ports: vec![51820],
                tcp_ports,
                tls_ports,
                priority: 0,
            }],
        }
    }

    #[test]
    fn test_to_settings_string_escapes_commas() {
        // Raw JSON separators (,) are replaced with \, so nmcli won't misparse them.
        // The escaping prepends a backslash; commas still appear but every one is preceded by \.
        let s = minimal_settings(vec![443], vec![8443])
            .to_settings_string()
            .unwrap();
        assert!(s.contains(r"\,"), "escaped commas must be present, got: {s}");
        // No bare (unescaped) comma should remain.
        let bare_comma = s.chars().zip(s.chars().skip(1)).any(|(prev, c)| c == ',' && prev != '\\');
        assert!(!bare_comma, "bare comma found in: {s}");
    }

    #[test]
    fn test_settings_round_trip_preserves_ports() {
        let original = minimal_settings(vec![443], vec![8443]);
        let serialized = original.to_settings_string().unwrap();
        let deserialized = Settings::from_settings_str(&serialized).unwrap();
        assert_eq!(deserialized.version, VERSION);
        assert_eq!(deserialized.peers[0].tcp_ports, vec![443u16]);
        assert_eq!(deserialized.peers[0].tls_ports, vec![8443u16]);
    }

    #[test]
    fn test_settings_round_trip_with_pcap_file() {
        let original = Settings {
            version: VERSION,
            pcap_file: Some(PcapFileInfo {
                file_path: "/tmp/cap.pcap".into(),
                max_bytes: Some(1024),
                mode: FileWriteMode::Overwrite,
            }),
            peers: vec![],
        };
        let serialized = original.to_settings_string().unwrap();
        let deserialized = Settings::from_settings_str(&serialized).unwrap();
        let pcap = deserialized.pcap_file.unwrap();
        assert_eq!(pcap.file_path, std::path::PathBuf::from("/tmp/cap.pcap"));
        assert_eq!(pcap.max_bytes, Some(1024));
        assert!(matches!(pcap.mode, FileWriteMode::Overwrite));
    }

    // ---- TryFrom<PeerInfo> ----

    fn valid_peer() -> PeerInfo {
        PeerInfo {
            id: "server1".into(),
            endpoint: "192.168.1.1".into(),
            public_key: BASE64_STANDARD.encode([0xabu8; 32]),
            udp_ports: vec![51820],
            tcp_ports: vec![443],
            tls_ports: vec![8443],
            priority: 1,
        }
    }

    #[test]
    fn test_peer_info_conversion_succeeds() {
        let converted: protun::api::connection::PeerInfo =
            valid_peer().try_into().unwrap();
        assert_eq!(converted.peer_id, "server1");
        assert_eq!(converted.udp_ports, vec![51820u16]);
        assert_eq!(converted.tcp_ports, vec![443u16]);
        assert_eq!(converted.tls_ports, vec![8443u16]);
        assert_eq!(converted.priority, 1);
        assert_eq!(converted.server_public_key.0, [0xabu8; 32]);
    }

    #[test]
    fn test_peer_info_rejects_ipv6_endpoint() {
        let mut peer = valid_peer();
        peer.endpoint = "::1".into();
        let result: crate::proton::vpn::Result<protun::api::connection::PeerInfo> =
            peer.try_into();
        match result {
            Err(crate::proton::vpn::Error::InvalidState(msg)) => {
                assert!(msg.contains("IPv6 endpoint not supported"), "unexpected message: {msg}");
                assert!(msg.contains("::1"), "message should include the address: {msg}");
            }
            other => panic!("expected InvalidState, got {other:?}"),
        }
    }

    #[test]
    fn test_peer_info_rejects_invalid_base64_key() {
        let mut peer = valid_peer();
        peer.public_key = "not-valid-base64!!!".into();
        let result: crate::proton::vpn::Result<protun::api::connection::PeerInfo> =
            peer.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_peer_info_rejects_wrong_length_key() {
        let mut peer = valid_peer();
        peer.public_key = BASE64_STANDARD.encode([0u8; 16]); // 16 bytes, not 32
        let result: crate::proton::vpn::Result<protun::api::connection::PeerInfo> =
            peer.try_into();
        assert!(matches!(result, Err(crate::proton::vpn::Error::TryFromSlice(_))));
    }

    // ---- TryFrom<PcapFileInfo> ----

    #[test]
    fn test_pcap_file_info_append_mode() {
        let info = PcapFileInfo {
            file_path: "/tmp/capture.pcap".into(),
            max_bytes: Some(4096),
            mode: FileWriteMode::Append,
        };
        let converted: protun::api::connection::PcapFileInfo = info.try_into().unwrap();
        assert_eq!(converted.max_bytes, Some(4096));
        assert!(matches!(
            converted.file,
            protun::api::connection::PcapFile::Path {
                mode: protun::api::connection::FileWriteMode::Append,
                ..
            }
        ));
    }

    #[test]
    fn test_pcap_file_info_overwrite_mode() {
        let info = PcapFileInfo {
            file_path: "/tmp/capture.pcap".into(),
            max_bytes: None,
            mode: FileWriteMode::Overwrite,
        };
        let converted: protun::api::connection::PcapFileInfo = info.try_into().unwrap();
        assert!(matches!(
            converted.file,
            protun::api::connection::PcapFile::Path {
                mode: protun::api::connection::FileWriteMode::Overwrite,
                ..
            }
        ));
    }

    #[test]
    fn test_pcap_file_info_non_utf8_path_returns_error() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let info = PcapFileInfo {
            file_path: std::path::PathBuf::from(OsString::from_vec(vec![0xFF, 0xFE])),
            max_bytes: None,
            mode: FileWriteMode::Append,
        };
        let result: crate::proton::vpn::Result<protun::api::connection::PcapFileInfo> =
            info.try_into();
        assert!(matches!(result, Err(crate::proton::vpn::Error::InvalidState(_))));
    }

    // ---- get_private_key_from_secrets ----

    #[test]
    fn test_get_private_key_valid() {
        let key_bytes = [7u8; 32];
        let mut secrets: ConnectionSettingsSection = HashMap::new();
        secrets.insert("private-key".into(), str_owned_value(&BASE64_STANDARD.encode(key_bytes)));
        assert_eq!(get_private_key_from_secrets(&mut secrets).unwrap(), key_bytes);
    }

    #[test]
    fn test_get_private_key_wrong_length() {
        let mut secrets: ConnectionSettingsSection = HashMap::new();
        secrets.insert("private-key".into(), str_owned_value(&BASE64_STANDARD.encode([0u8; 16])));
        let result = get_private_key_from_secrets(&mut secrets);
        assert!(matches!(result, Err(crate::proton::vpn::Error::ValueError(_))));
    }

    #[test]
    fn test_get_private_key_invalid_base64() {
        let mut secrets: ConnectionSettingsSection = HashMap::new();
        secrets.insert("private-key".into(), str_owned_value("not-base64!!!"));
        let result = get_private_key_from_secrets(&mut secrets);
        assert!(matches!(result, Err(crate::proton::vpn::Error::ValueError(_))));
    }

    #[test]
    fn test_get_private_key_missing_key() {
        let mut secrets: ConnectionSettingsSection = HashMap::new();
        let result = get_private_key_from_secrets(&mut secrets);
        assert!(matches!(result, Err(crate::proton::vpn::Error::MissingSetting(_))));
    }
}