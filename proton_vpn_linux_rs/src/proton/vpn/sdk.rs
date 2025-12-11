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
//! High-level VPN SDK interface.
//!
//! Provides a simple API for managing VPN connections.

pub use super::connection_manager::*;

#[derive(Debug)]
pub struct Sdk {
    connection_manager: ConnectionManager,
}

impl Default for Sdk {
    fn default() -> Self {
        Self::new()
    }
}

impl Sdk {
    pub fn new() -> Self {
        Sdk {
            connection_manager: ConnectionManager::new(),
        }
    }

    pub fn connection_manager(&mut self) -> &mut ConnectionManager {
        &mut self.connection_manager
    }
}
