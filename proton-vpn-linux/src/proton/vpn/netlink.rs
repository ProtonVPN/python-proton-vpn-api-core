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
//! Netlink operations for VPN interface management.
//!
//! This module provides async functions for interface configuration (up, MTU).

use futures::stream::TryStreamExt;
use rtnetlink::new_connection;

use super::{Error, Result};

/// A wrapper around rtnetlink Handle for interface operations.
pub struct NetlinkHandle {
    handle: rtnetlink::Handle, // TODO: LT Record the dependency we're using
    // so it can be checked.
    // Keep the connection task alive
    _connection_task: tokio::task::JoinHandle<()>,
}

impl NetlinkHandle {
    /// Create a new netlink handle.
    pub fn new() -> Result<Self> {
        let (connection, handle, _) = new_connection()?;

        Ok(Self {
            handle,
            _connection_task: tokio::spawn(connection),
        })
    }

    /// Get interface index by name.
    async fn get_interface_index(&self, name: &str) -> Result<u32> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();

        if let Some(link) = links.try_next().await? {
            Ok(link.header.index)
        } else {
            Err(Error::IO(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Interface {} not found", name),
            )))
        }
    }

    /// Configure interface: set UP and MTU.
    pub async fn configure_interface(
        &self,
        name: &str,
        mtu: u32,
    ) -> Result<()> {
        self.handle
            .link()
            .set(self.get_interface_index(name).await?)
            .mtu(mtu)
            .up()
            .execute()
            .await?;

        log::info!("Interface {} configured: UP, MTU={}", name, mtu);
        Ok(())
    }
}
