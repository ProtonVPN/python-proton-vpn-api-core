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
//! Parameters the kill switch needs to let VPN traffic through.

use std::net::IpAddr;

use super::error::{Error, Result};

pub use crate::FWMARK as DEFAULT_FWMARK;
pub use crate::TUNNEL_IFACE as DEFAULT_TUNNEL_IFACE;

/// What the kill switch must allow through while blocking everything else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The fwmark WireGuard stamps on the packets it sends to the VPN server.
    pub fwmark: u32,

    /// Name of the WireGuard tunnel interface. Matched by name rather than by
    /// index, so the kill switch can be enabled *before* the interface exists.
    pub tunnel_iface: String,

    /// VPN server IP. When set, traffic to it is allowed during the connecting
    /// phase, before the tunnel is up and WireGuard starts marking packets.
    /// When `None`, that rule is skipped.
    pub server_ip: Option<IpAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            fwmark: DEFAULT_FWMARK,
            tunnel_iface: DEFAULT_TUNNEL_IFACE.to_owned(),
            server_ip: None,
        }
    }
}

/// Parse an fwmark written in decimal or in `0x`-prefixed hexadecimal.
pub fn parse_fwmark(fwmark: &str) -> Result<u32> {
    let parsed = match fwmark
        .strip_prefix("0x")
        .or_else(|| fwmark.strip_prefix("0X"))
    {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => fwmark.parse::<u32>(),
    };

    parsed.map_err(|e| Error::InvalidFwmark(fwmark.to_owned(), e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_targets_the_proton_tunnel() {
        let config = Config::default();

        assert_eq!(config.fwmark, DEFAULT_FWMARK);
        assert_eq!(config.tunnel_iface, "proton0");
        assert_eq!(config.server_ip, None);
    }

    #[test]
    fn parse_fwmark_accepts_decimal() {
        assert_eq!(parse_fwmark("245447468").unwrap(), DEFAULT_FWMARK);
        assert_eq!(parse_fwmark("0").unwrap(), 0);
    }

    #[test]
    fn parse_fwmark_accepts_hex_in_either_case() {
        assert_eq!(parse_fwmark("0x2a").unwrap(), 42);
        assert_eq!(parse_fwmark("0X2A").unwrap(), 42);
    }

    #[test]
    fn parse_fwmark_rejects_malformed_input() {
        for invalid in ["", "0x", "nope", " 42", "-1"] {
            assert!(
                parse_fwmark(invalid).is_err(),
                "{invalid:?} should not parse"
            );
        }
    }

    #[test]
    fn parse_fwmark_rejects_hex_without_prefix() {
        // Without the 0x prefix it is read as decimal, so hex-only digits
        // must not silently parse as some other number.
        assert!(parse_fwmark("2a").is_err());
    }

    #[test]
    fn parse_fwmark_rejects_values_above_u32_max() {
        assert!(parse_fwmark("4294967296").is_err());
        assert!(parse_fwmark("0x100000000").is_err());
    }
}
