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

//! Everything for obtaining the settings for a VPN connection from the
//! NetworkManager connection settings.

use std::net::IpAddr;

#[cfg(feature = "python")]
use pyo3::prelude::*;

use base64::prelude::*;
use std::collections::HashMap;
use zbus::zvariant::OwnedValue;
use std::mem::ManuallyDrop;
use std::os::fd::AsRawFd;
use super::super::core::{FileWriteMode, PcapStart, PeerInfo};

use super::error::{Error, Result};

pub type ConnectionSettingsSection = HashMap<String, OwnedValue>;
pub type ConnectionSettings = HashMap<String, ConnectionSettingsSection>;

/// Default TUN interface name prefix if connection name is not available
const DEFAULT_TUN_PREFIX: &str = "protun";

/// A version number for the expected structure of the settings,
/// for now we just use this to guard against loading settings that are
/// using an outdated format.
pub const VERSION: u32 = 1;
pub const SETTINGS_KEY: &str = "settings";

#[derive(Debug, Clone)]
pub struct InterfaceParams<A> {
    pub name: String,
    pub address: A,
    pub prefix: u32,
    pub dns: Vec<A>,
}

impl From<PcapStart> for protun::api::connection::PcapFileInfo {
    fn from(params: PcapStart) -> Self {
        // ManuallyDrop prevents OwnedFd's Drop from closing the fd as we hand
        // ownership of the raw fd to protun.
        let raw_fd = ManuallyDrop::new(params.file_info.fd.0).as_raw_fd();
        protun::api::connection::PcapFileInfo {
            file: protun::api::connection::PcapFile::Fd(raw_fd),
            max_bytes: if params.max_bytes == 0 { None } else { Some(params.max_bytes) },
        }
    }
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Settings {
    pub version : u32,
    pub peers: Vec<PeerInfo>,
}

#[derive(Debug, Clone)]
pub struct ConnectionParams {
    pub ipv4_interface: InterfaceParams<std::net::Ipv4Addr>,
    pub ipv6_interface: Option<InterfaceParams<std::net::Ipv6Addr>>,
    pub private_key: [u8; 32],
    pub peers: Vec<protun::api::connection::PeerInfo>,
    pub user: u32,
}

/// Convert a value to a type that can be stored in NM settings (string, int, array, etc).
/// Any type that implements serde Serialize and Deserialize will be implemented
/// as a ProtunSetting, which can be easily converted to/from a string for storage in NM settings.
pub trait ProtunSetting: Sized {
    fn from_settings_str(s: &str) -> Result<Self>;
    fn to_settings_string(&self) -> Result<String>;
}

impl<T: serde::Serialize + serde::de::DeserializeOwned> ProtunSetting for T {
    fn to_settings_string(&self) -> Result<String> {
        // nmcli does not allow commas in values, so we need to escape them as \.
        // This is fine so long as we are consistent in both directions.
        //
        // So if we're manually creating a nmcli connection we should use
        // nm-protun-service with the cli option, which will produce the
        // nmcli command with the correct escaping.
        //
        // The linux client will do the escaping correctly.
        Ok(serde_json::to_string(self)
            .map_err(|_| Error::ValueError("Failed to serialize".into()))?
            .replace(",", r"\,"))
    }

    fn from_settings_str(s: &str) -> Result<Self> {
        Ok(serde_json::from_str::<Self>(&s.replace(r"\,", ","))?)
    }
}

impl TryFrom<PeerInfo> for protun::api::connection::PeerInfo {
    type Error = Error;

    fn try_from(peer: PeerInfo) -> Result<Self> {
        let server_ip: IpAddr = peer.endpoint.parse()?;

        let public_key: [u8; 32] = BASE64_STANDARD
            .decode(peer.public_key.as_bytes())?
            .as_slice()
            .try_into()?;

        // Double check the address is not ipv6 address
        if let IpAddr::V6(address) = &server_ip {
            return Err(Error::InvalidState(
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
    fn take_value<T>(&mut self, key: &str) -> Result<T>
    where
        T: TryFrom<OwnedValue>;
}

impl TakeValue for ConnectionSettingsSection {
    fn take_value<T>(&mut self, key: &str) -> Result<T>
    where
        T: TryFrom<OwnedValue>,
    {
        let value = self
            .remove(key)
            .ok_or_else(|| Error::MissingSetting(key.into()))?;
        value.try_into().map_err(|_| {
            Error::ValueError(format!("Failed to convert '{}'", key))
        })
    }
}

trait GetSection {
    fn get_section(
        &mut self,
        key: &str,
    ) -> Result<&mut ConnectionSettingsSection>;
}

impl GetSection for HashMap<String, ConnectionSettingsSection> {
    fn get_section(
        &mut self,
        key: &str,
    ) -> Result<&mut ConnectionSettingsSection> {
        self.get_mut(key)
            .ok_or_else(|| Error::MissingSetting(key.into()))
    }
}

/// Extract IPv6 configuration (address, prefix, dns) from ipv6 settings
fn extract_ipv6_config(
    name: String,
    ipv6: Option<&mut ConnectionSettingsSection>,
) -> Result<Option<InterfaceParams::<std::net::Ipv6Addr>>> {
    match ipv6 {
        None => Ok(None),
        Some(ipv6) => {
            let address_data: Vec<HashMap<String, OwnedValue>> =
                match ipv6.take_value("address-data") {
                    Ok(data) => data,
                    Err(_) => return Ok(None),
                };
            let Some(mut first) = address_data.into_iter().next() else {
                return Ok(None);
            };
            let address: String = first
                .remove("address")
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| Error::MissingSetting("ipv6.address-data[0].address".into()))?;
            let prefix: u32 = first
                .remove("prefix")
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| Error::MissingSetting("ipv6.address-data[0].prefix".into()))?;
            let address: std::net::Ipv6Addr = address
                .parse()
                .map_err(|_| Error::ValueError("Invalid IPv6 address".into()))?;

            let dns: Vec<std::net::Ipv6Addr> = ipv6
                .take_value::<Vec<Vec<u8>>>("dns")
                .unwrap_or_default()
                .into_iter()
                .filter_map(|bytes| {
                    let arr: [u8; 16] = bytes.try_into().ok()?;
                    Some(std::net::Ipv6Addr::from(arr))
                })
                .collect();

            Ok(Some(InterfaceParams::<std::net::Ipv6Addr>{
                name,
                address,
                prefix,
                dns
            }))
        }
    }
}

/// Extract IPv4 configuration (address, prefix, DNS) from ipv4 settings
fn extract_ipv4_config(
    name: String,
    ipv4: &mut ConnectionSettingsSection,
) -> Result<InterfaceParams::<std::net::Ipv4Addr>> {
    // TODO: LT: Look into address-data, as addresses is deprecated.
    let mut addr_array = ipv4
        .take_value::<Vec<Vec<u32>>>("addresses")?
        .into_iter()
        .map(|v| -> Result<(u32, u32)> {
            let array = TryInto::<[u32; 3]>::try_into(v).map_err(|_| {
                Error::ValueError("Invalid addresses entry".into())
            })?;
            Ok((array[0], array[1]))
        });

    let (addr_u32, prefix) = addr_array.next().ok_or_else(|| {
        Error::MissingSetting("ipv4.addresses[0]".into())
    })??;

    // Address is in network byte order
    let address = std::net::Ipv4Addr::from_bits(u32::from_be(addr_u32));

    // dns is au - array of u32 in network byte order
    let dns: Vec<std::net::Ipv4Addr> = ipv4
        .take_value::<Vec<u32>>("dns")?
        .into_iter()
        .map(|ip| std::net::Ipv4Addr::from_bits(u32::from_be(ip)))
        .collect();

    Ok(InterfaceParams::<std::net::Ipv4Addr>{
        name,
        address,
        prefix,
        dns
    })
}

pub fn read_json_key<T>(key: &str, data: &mut  ConnectionSettingsSection) -> Result<T>
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
) -> Result<ConnectionParams> {
    // Get interface name and user (read-only, before we consume settings)
    let interface_name = get_interface_name(&connection_settings)
        .map(|name| sanitize_interface_name(&name))
        .unwrap_or_else(|| DEFAULT_TUN_PREFIX.to_string());
    let user = get_user_from_permissions(&connection_settings)?;

    // Extract WireGuard settings from NM connection settings
    let vpn = connection_settings.get_section("vpn")?;
    let mut data: ConnectionSettingsSection = vpn.take_value("data")?;

    let settings = read_json_key::<Settings>(SETTINGS_KEY, &mut data)?;

    if settings.version != VERSION {
        return Err(Error::InvalidState(format!(
            "Settings version mismatch: expected {}, got {}",
            VERSION, settings.version
        )));
    }

    let mut secrets: ConnectionSettingsSection = vpn.take_value("secrets")?;

    let ipv6_interface = extract_ipv6_config(
        interface_name.clone(),
        connection_settings.get_mut("ipv6")
    )?;

    let ipv4_interface =
        extract_ipv4_config(
            interface_name.clone(),
            connection_settings.get_section("ipv4")?
    )?;

    // Deserialize peers with implicit conversion to protun PeerInfo.
    let peers = settings.peers
        .into_iter()
        .map(|peer| peer.try_into())
        .collect::<Result<Vec<protun::api::connection::PeerInfo>>>()?;

    // Get private key from vpn.secrets section
    let private_key = get_private_key_from_secrets(&mut secrets)?;

    Ok(ConnectionParams {
        ipv4_interface,
        ipv6_interface,
        peers,
        private_key,
        user,
    })
}

/// Resolve a Unix username to a UID.
fn username_to_uid(username: &str) -> Result<u32> {
    nix::unistd::User::from_name(username)
        .map_err(|e| Error::InvalidState(format!("error looking up user {:?}: {}", username, e)))?
        .ok_or_else(|| Error::InvalidState(format!("user {:?} not found", username)))
        .map(|u| u.uid.as_raw())
}

/// Extract the first `user:` entry from `connection.permissions` and resolve it to a UID.
///
/// NM permission entries have the form `"user:<username>"` or `"user:<username>:"`.
/// Returns `Ok(None)` if no user permission entry is present.
/// Returns `Err` if a username is found but cannot be resolved to a UID.
fn get_user_from_permissions(settings: &ConnectionSettings) -> Result<u32> {
    fn find_user_permission_entry(settings: &ConnectionSettings) -> Option<String> {
        let perms: Vec<String> =
            settings.get("connection")?
                    .get("permissions")?
                    .clone().try_into().ok()?;
        for p in perms {
            if let Some((prefix, rest)) = p.split_once(':') {
                if prefix == "user" {
                    return Some(rest.trim_end_matches(':').to_string());
                }
            }
        }
        None
    }

    let username = find_user_permission_entry(settings).ok_or_else(
        || Error::InvalidState("No user permission entry found".into())
    )?;

    username_to_uid(&username)
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
) -> Result<[u8; 32]> {

    let private_key_bytes : [u8;32] = BASE64_STANDARD
        .decode(secrets.take_value::<String>("private-key")?.as_bytes())
        .map_err(|e| {
            Error::ValueError(format!("Failed to decode private key: {}", e))
        })?.try_into().map_err(|_| {
            Error::ValueError("Private key must be 32 bytes".into())
        })?;

    Ok(private_key_bytes)
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
) -> Result<bool> {
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
        let result: Result<protun::api::connection::PeerInfo> =
            peer.try_into();
        match result {
            Err(Error::InvalidState(msg)) => {
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
        let result: Result<protun::api::connection::PeerInfo> =
            peer.try_into();
        assert!(result.is_err());
    }

    #[test]
    fn test_peer_info_rejects_wrong_length_key() {
        let mut peer = valid_peer();
        peer.public_key = BASE64_STANDARD.encode([0u8; 16]); // 16 bytes, not 32
        let result: Result<protun::api::connection::PeerInfo> =
            peer.try_into();
        assert!(matches!(result, Err(Error::TryFromSlice(_))));
    }

    // ---- extract_ipv6_config ----

    fn u32_owned_value(n: u32) -> OwnedValue {
        OwnedValue::try_from(Value::from(n)).unwrap()
    }

    fn make_ipv6_section(address: &str, prefix: u32) -> ConnectionSettingsSection {
        let mut entry: HashMap<String, OwnedValue> = HashMap::new();
        entry.insert("address".into(), str_owned_value(address));
        entry.insert("prefix".into(), u32_owned_value(prefix));
        let address_data = vec![entry];
        let mut section = ConnectionSettingsSection::new();
        section.insert(
            "address-data".into(),
            OwnedValue::try_from(Value::from(address_data)).unwrap(),
        );
        section
    }

    const TEST_IPV6_ADDR: &str = "fd00::1";
    const TEST_IF_NAME: &str = "protun0";
    const TEST_IPV4_ADDR: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 0, 0, 1);
    const TEST_DNS_ADDR: std::net::Ipv4Addr = std::net::Ipv4Addr::new(8, 8, 8, 8);

    fn addr_u32(ip: std::net::Ipv4Addr) -> u32 {
        // extract_ipv4_config reads: Ipv4Addr::from_bits(u32::from_be(x))
        // so to produce ip from x: x = u32::to_be(ip.to_bits())
        u32::to_be(ip.to_bits())
    }

    fn make_ipv4_section(
        address: std::net::Ipv4Addr,
        prefix: u32,
        dns: Vec<std::net::Ipv4Addr>,
    ) -> ConnectionSettingsSection {
        let mut section = ConnectionSettingsSection::new();
        section.insert(
            "addresses".into(),
            OwnedValue::try_from(Value::from(vec![
                vec![addr_u32(address), prefix, 0u32],
            ])).unwrap(),
        );
        let dns_u32: Vec<u32> = dns.into_iter().map(addr_u32).collect();
        section.insert(
            "dns".into(),
            OwnedValue::try_from(Value::from(dns_u32)).unwrap(),
        );
        section
    }

    // ---- extract_ipv4_config / extract_ipv6_config (shared scenarios) ----

    #[test]
    fn test_valid_config_no_dns() {
        let mut s = make_ipv4_section(TEST_IPV4_ADDR, 24, vec![]);
        let r = extract_ipv4_config(TEST_IF_NAME.into(), &mut s).unwrap();
        assert_eq!(r.name, TEST_IF_NAME);
        assert_eq!(r.address, TEST_IPV4_ADDR);
        assert_eq!(r.prefix, 24);
        assert!(r.dns.is_empty());

        let mut s = make_ipv6_section(TEST_IPV6_ADDR, 64);
        let r = extract_ipv6_config(TEST_IF_NAME.into(), Some(&mut s)).unwrap().unwrap();
        assert_eq!(r.name, TEST_IF_NAME);
        assert_eq!(r.address, TEST_IPV6_ADDR.parse::<std::net::Ipv6Addr>().unwrap());
        assert_eq!(r.prefix, 64);
        assert!(r.dns.is_empty());
    }

    #[test]
    fn test_valid_config_with_dns() {
        let mut s = make_ipv4_section(TEST_IPV4_ADDR, 24, vec![TEST_DNS_ADDR]);
        let r = extract_ipv4_config(TEST_IF_NAME.into(), &mut s).unwrap();
        assert_eq!(r.dns, vec![TEST_DNS_ADDR]);

        let ipv6_dns_bytes: Vec<Vec<u8>> = vec![
            TEST_IPV6_ADDR.parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec()
        ];
        let mut s = make_ipv6_section(TEST_IPV6_ADDR, 64);
        s.insert("dns".into(), OwnedValue::try_from(Value::from(ipv6_dns_bytes)).unwrap());
        let r = extract_ipv6_config(TEST_IF_NAME.into(), Some(&mut s)).unwrap().unwrap();
        assert_eq!(r.dns, vec![TEST_IPV6_ADDR.parse::<std::net::Ipv6Addr>().unwrap()]);
    }

    // ---- extract_ipv4_config (specific) ----

    #[test]
    fn test_ipv4_missing_addresses_returns_error() {
        let mut section = ConnectionSettingsSection::new();
        let result = extract_ipv4_config(TEST_IF_NAME.into(), &mut section);
        assert!(matches!(result, Err(Error::MissingSetting(_))));
    }

    #[test]
    fn test_ipv4_empty_addresses_returns_error() {
        let mut section = ConnectionSettingsSection::new();
        section.insert(
            "addresses".into(),
            OwnedValue::try_from(Value::from(Vec::<Vec<u32>>::new())).unwrap(),
        );
        section.insert(
            "dns".into(),
            OwnedValue::try_from(Value::from(Vec::<u32>::new())).unwrap(),
        );
        let result = extract_ipv4_config(TEST_IF_NAME.into(), &mut section);
        assert!(matches!(result, Err(Error::MissingSetting(_))));
    }

    #[test]
    fn test_ipv4_malformed_address_entry_returns_error() {
        let mut section = ConnectionSettingsSection::new();
        section.insert(
            "addresses".into(),
            OwnedValue::try_from(Value::from(vec![vec![0u32, 24u32]])).unwrap(), // 2 elements, not 3
        );
        section.insert(
            "dns".into(),
            OwnedValue::try_from(Value::from(Vec::<u32>::new())).unwrap(),
        );
        let result = extract_ipv4_config(TEST_IF_NAME.into(), &mut section);
        assert!(matches!(result, Err(Error::ValueError(_))));
    }

    // ---- extract_ipv6_config (specific) ----

    #[test]
    fn test_ipv6_none_section_returns_none() {
        let result = extract_ipv6_config(TEST_IF_NAME.into(), None).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_ipv6_missing_address_data_returns_none() {
        let mut section = ConnectionSettingsSection::new();
        let result = extract_ipv6_config(TEST_IF_NAME.into(), Some(&mut section)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_ipv6_missing_address_field_returns_error() {
        let mut entry: HashMap<String, OwnedValue> = HashMap::new();
        entry.insert("prefix".into(), u32_owned_value(128));
        let mut section = ConnectionSettingsSection::new();
        section.insert(
            "address-data".into(),
            OwnedValue::try_from(Value::from(vec![entry])).unwrap(),
        );
        let result = extract_ipv6_config(TEST_IF_NAME.into(), Some(&mut section));
        assert!(matches!(result, Err(Error::MissingSetting(_))));
    }

    #[test]
    fn test_ipv6_malformed_dns_bytes_are_skipped() {
        let mut section = make_ipv6_section(TEST_IPV6_ADDR, 128);
        let bad_dns: Vec<Vec<u8>> = vec![vec![0u8; 4]]; // 4 bytes, not 16
        section.insert("dns".into(), OwnedValue::try_from(Value::from(bad_dns)).unwrap());
        let result = extract_ipv6_config(TEST_IF_NAME.into(), Some(&mut section))
            .unwrap()
            .unwrap();
        assert!(result.dns.is_empty());
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
        assert!(matches!(result, Err(Error::ValueError(_))));
    }

    #[test]
    fn test_get_private_key_invalid_base64() {
        let mut secrets: ConnectionSettingsSection = HashMap::new();
        secrets.insert("private-key".into(), str_owned_value("not-base64!!!"));
        let result = get_private_key_from_secrets(&mut secrets);
        assert!(matches!(result, Err(Error::ValueError(_))));
    }

    #[test]
    fn test_get_private_key_missing_key() {
        let mut secrets: ConnectionSettingsSection = HashMap::new();
        let result = get_private_key_from_secrets(&mut secrets);
        assert!(matches!(result, Err(Error::MissingSetting(_))));
    }
}
