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
//! D-Bus wire representation of the kill switch configuration.

use std::net::IpAddr;

use super::super::config::FirewallConfig;
use super::super::error::{ConfigError, Error, Result};

/// [`FirewallConfig`] as it crosses D-Bus. Wire format: `(ussb)`.
///
/// D-Bus has neither an optional type nor an IP-address type, so `server_ip`
/// carries the address as a string and uses the **empty string to mean "no
/// server IP"**. That keeps the signature callable by hand from `busctl` and
/// from any language, at the cost of encoding absence by convention.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    zvariant::Type,
)]
pub struct ConfigWire {
    /// The fwmark WireGuard stamps on packets it sends to the VPN server,
    /// or 0 for the default.
    pub fwmark: u32,

    /// Name of the WireGuard tunnel interface, or the empty string for the
    /// default.
    pub tunnel_iface: String,

    /// VPN server IP, or the empty string for none.
    pub server_ip: String,

    /// Whether the rules should survive a reboot. `false` is the default,
    /// same as `0` and `""` are for the fields above.
    pub permanent: bool,
}

impl From<&FirewallConfig> for ConfigWire {
    fn from(config: &FirewallConfig) -> Self {
        Self {
            fwmark: config.fwmark,
            tunnel_iface: config.tunnel_iface.clone(),
            server_ip: config
                .server_ip
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            permanent: config.permanent,
        }
    }
}

impl TryFrom<ConfigWire> for FirewallConfig {
    type Error = Error;

    /// Validate a wire config coming from an untrusted caller, applying the
    /// defaults for the fields it left empty.
    ///
    /// Defaulting here rather than in every caller keeps the fwmark and the
    /// tunnel interface name defined in exactly one place.
    fn try_from(wire: ConfigWire) -> Result<Self> {
        let defaults = FirewallConfig::default();

        let server_ip = if wire.server_ip.is_empty() {
            None
        } else {
            Some(wire.server_ip.parse::<IpAddr>().map_err(|e| {
                ConfigError::ServerIp(wire.server_ip.clone(), e)
            })?)
        };

        Ok(Self {
            // 0 is not a usable fwmark - a rule matching mark == 0 would match
            // every unmarked packet - so it is free to mean "use the default".
            fwmark: if wire.fwmark == 0 {
                defaults.fwmark
            } else {
                wire.fwmark
            },
            tunnel_iface: if wire.tunnel_iface.is_empty() {
                defaults.tunnel_iface
            } else {
                wire.tunnel_iface
            },
            server_ip,
            permanent: wire.permanent,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use zvariant::Type as _;

    use super::*;

    fn roundtrip(wire: &ConfigWire) -> ConfigWire {
        let ctx = zvariant::serialized::Context::new_dbus(zvariant::LE, 0);
        let data = zvariant::to_bytes(ctx, wire).expect("serialization failed");
        let (result, _) = data.deserialize().expect("deserialization failed");
        result
    }

    #[test]
    fn wire_signature_is_ussb() {
        // Callers in other languages hardcode this signature, so a change
        // here breaks them.
        assert_eq!(*ConfigWire::SIGNATURE, "(ussb)");
    }

    #[test]
    fn wire_roundtrips_over_dbus() {
        let wire = ConfigWire {
            fwmark: 245_447_468,
            tunnel_iface: "proton0".to_owned(),
            server_ip: "185.159.157.1".to_owned(),
            permanent: true,
        };

        assert_eq!(roundtrip(&wire), wire);
    }

    #[test]
    fn config_survives_a_round_trip_through_the_wire() {
        let config = FirewallConfig {
            fwmark: 42,
            tunnel_iface: "proton0".to_owned(),
            server_ip: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            permanent: true,
        };

        let wire = roundtrip(&ConfigWire::from(&config));

        assert_eq!(FirewallConfig::try_from(wire).unwrap(), config);
    }

    #[test]
    fn absent_server_ip_maps_to_the_empty_string_and_back() {
        let config = FirewallConfig {
            server_ip: None,
            ..FirewallConfig::default()
        };

        let wire = ConfigWire::from(&config);
        assert_eq!(wire.server_ip, "");

        assert_eq!(FirewallConfig::try_from(wire).unwrap().server_ip, None);
    }

    #[test]
    fn rejects_a_malformed_server_ip() {
        let wire = ConfigWire {
            fwmark: 42,
            tunnel_iface: "proton0".to_owned(),
            server_ip: "not-an-ip".to_owned(),
            permanent: false,
        };

        let err = FirewallConfig::try_from(wire).unwrap_err();

        assert!(matches!(err, Error::Config(ConfigError::ServerIp(..))));
    }

    #[test]
    fn empty_fields_fall_back_to_the_defaults() {
        // What a caller sends when it wants the service to decide.
        let wire = ConfigWire {
            fwmark: 0,
            tunnel_iface: String::new(),
            server_ip: String::new(),
            permanent: false,
        };

        assert_eq!(FirewallConfig::try_from(wire).unwrap(), FirewallConfig::default());
    }

    #[test]
    fn permanent_is_never_defaulted() {
        // The other fields treat the zero value as "service decides"; this one
        // must not, or a caller sending defaults would silently get permanence.
        let wire = ConfigWire {
            fwmark: 0,
            tunnel_iface: String::new(),
            server_ip: String::new(),
            permanent: true,
        };

        assert!(FirewallConfig::try_from(wire).unwrap().permanent);
    }

    #[test]
    fn explicit_values_override_the_defaults() {
        let wire = ConfigWire {
            fwmark: 42,
            tunnel_iface: "wg0".to_owned(),
            server_ip: String::new(),
            permanent: false,
        };

        let config = FirewallConfig::try_from(wire).unwrap();

        assert_eq!(config.fwmark, 42);
        assert_eq!(config.tunnel_iface, "wg0");
    }
}
