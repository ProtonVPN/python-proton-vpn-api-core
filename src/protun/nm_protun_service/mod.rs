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
//! The NetworkManager VPN Plugin for ProtonVPN.
//!
//! This module contains the implementation of the protun VPN service.
//! The service provides a VPN connection to the ProtonVPN network and is
//! configured via the NetworkManager D-Bus API.

mod error;
mod interfaces;
mod run;
mod service;
mod types;
mod netlink;
pub mod wireguard_utils;

pub mod settings;
pub use run::run;
