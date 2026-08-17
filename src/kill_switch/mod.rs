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
//! Kill switch implementations.
//!
//! A kill switch blocks any traffic that would otherwise leave the host
//! outside the VPN tunnel, so a dropped or misconfigured connection cannot
//! leak the user's real IP address.
//!
//! [`firewall_kill_switch`] is the nftables-based implementation, intended
//! for WireGuard-based connections.

mod config;
mod error;

pub mod dbus;
pub mod firewall_kill_switch;

pub use firewall_kill_switch::FirewallKillSwitch;
pub use config::*;
pub use error::*;
