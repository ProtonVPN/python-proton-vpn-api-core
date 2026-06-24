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
mod command;
mod command_wire;
mod connection_manager;
mod parameters;
mod error;

pub use connection_manager::ConnectionManager;
pub use command::*;
pub use parameters::*;
pub use error::*;

pub const DBUS_SERVICE_NAME: &str = "org.freedesktop.NetworkManager.protun";
pub const DBUS_OBJECT_PATH: &str = "/org/freedesktop/NetworkManager/VPN/Plugin";
