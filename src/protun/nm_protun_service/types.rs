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

//! Types for the NetworkManager VPN Plugin these adhere to the NetworkManager D-Bus API.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use zbus::zvariant::{OwnedValue, SerializeDict, Type};

/// VPN connection state as defined by NetworkManager
/// TODO LT: Add link to debug docs for state changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NMVpnServiceState {
    /// The state of the VPN plugin is unknown.
    Unknown = 0,
    /// The VPN plugin is initialized.
    Init = 1,
    /// Not used.
    Shutdown = 2,
    /// The plugin is attempting to connect to a VPN server.
    Starting = 3,
    /// The plugin has connected to a VPN server.
    Started = 4,
    /// The plugin is disconnecting from the VPN server.
    Stopping = 5,
    /// The plugin has disconnected from the VPN server.
    Stopped = 6,
}

impl From<NMVpnServiceState> for u32 {
    fn from(state: NMVpnServiceState) -> u32 {
        state as u32
    }
}

/// VPN Config signal data sent to NetworkManager
///
/// This is serialized as a D-Bus dictionary (a{sv}).
#[derive(Debug, SerializeDict, Type)]
#[zvariant(signature = "a{sv}")]
pub struct VpnConfig {
    /// The TUN device name
    pub tundev: String,
    /// VPN gateway IP (network byte order)
    pub gateway: u32,
    /// Whether this VPN has IPv4 configuration
    #[zvariant(rename = "has-ip4")]
    pub has_ip4: bool,
    /// Whether this VPN has IPv6 configuration
    #[zvariant(rename = "has-ip6")]
    pub has_ip6: bool,
}

/// IPv6 configuration data sent to NetworkManager
///
/// This is serialized as a D-Bus dictionary (a{sv}).
/// Note: IP address must be a 16-byte array in network byte order.
#[derive(Debug, SerializeDict, Type)]
#[zvariant(signature = "a{sv}")]
pub struct Ip6Config {
    /// Internal VPN address (16 bytes, network byte order)
    pub address: Vec<u8>,
    /// Network prefix length
    pub prefix: u32,
    /// DNS servers (each a 16-byte array, network byte order)
    pub dns: Vec<Vec<u8>>,
    /// If true, don't set this VPN as the default route
    #[zvariant(rename = "never-default")]
    pub never_default: bool,
}

/// IPv4 configuration data sent to NetworkManager
///
/// This is serialized as a D-Bus dictionary (a{sv}).
/// Note: IP addresses must be in network byte order (big-endian).
#[derive(Debug, SerializeDict, Type)]
#[zvariant(signature = "a{sv}")]
pub struct Ip4Config {
    /// Internal VPN address (network byte order)
    pub address: u32,
    /// Network prefix length
    pub prefix: u32,
    /// DNS servers (network byte order)
    pub dns: Vec<u32>,
    /// MTU for the tunnel interface
    pub mtu: u32,
    /// If true, don't set this VPN as the default route
    #[zvariant(rename = "never-default")]
    pub never_default: bool,
    /// If true, don't automatically add routes derived by NM
    #[zvariant(rename = "ignore-auto-routes")]
    pub ignore_auto_routes: bool,
}
