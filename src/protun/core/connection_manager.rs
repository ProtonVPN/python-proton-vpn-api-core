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

//! ConnectionManager client for sending commands to the protun service.

use zbus::proxy;

use super::{Command, Error, Result};
#[cfg(feature = "python")]
use super::super::super::python::*;

#[cfg(feature = "python")]
use pyo3::prelude::*;

use super::{DBUS_SERVICE_NAME, DBUS_OBJECT_PATH};

// The proxy macro requires string literals, so the values are repeated there;
// the consts above are the single source of truth for runtime use.
// This macro generates a D-Bus ConnectionUpdatesProxy implementation from the ConnectionUpdates trait provided below
#[proxy(
    interface = "me.proton.vpn.protun",
    default_service = "org.freedesktop.NetworkManager.protun",
    default_path = "/org/freedesktop/NetworkManager/VPN/Plugin"
)]
trait ConnectionUpdates {
    async fn run(&self, command: &Command) -> zbus::Result<()>;
}

#[cfg_attr(feature = "python", pyo3::pyclass)]
#[derive(Debug, Clone)]
pub struct ConnectionManager {
    proxy: ConnectionUpdatesProxy<'static>,
}

impl ConnectionManager {
    pub async fn new() -> Result<Self> {
        let connection = zbus::Connection::system().await?;
        let proxy = ConnectionUpdatesProxy::builder(&connection)
            .destination(DBUS_SERVICE_NAME)?
            .path(DBUS_OBJECT_PATH)?
            .build()
            .await?;
        Ok(Self { proxy })
    }

    pub async fn run(&self, command: Command) -> Result<()> {
        self.proxy.run(&command).await?;
        Ok(())
    }
}

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl ConnectionManager {
    /// Connects to the protun D-Bus service and returns a ConnectionManager.
    ///
    /// Usage: `client = await ConnectionManager.new()`
    #[staticmethod]
    #[pyo3(name = "new")]
    pub fn py_new(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
        await_py!(py, ConnectionManager::new())
    }

    /// Sends a command to the protun service.
    ///
    /// Usage: `await client.run(command)`
    #[pyo3(name = "run")]
    pub fn py_run<'p>(
        &self,
        py: Python<'p>,
        command: Command,
    ) -> PyResult<Bound<'p, PyAny>> {
        await_py!(py, self.run(command))
    }
}
