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

//! The entry point for the protun VPN service.
//!
//! Responsible for starting the dbus connection and registering the plugin.
//!
//! Reference: https://networkmanager.dev/docs/api/latest/gdbus-org.freedesktop.NetworkManager.VPN.Plugin.html

use std::sync::Arc;

use zbus::Connection;

use super::interfaces::new_interfaces;

use super::super::core::{DBUS_SERVICE_NAME, DBUS_OBJECT_PATH};

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    log::info!("Starting Proton VPN NetworkManager plugin");

    let shutdown = Arc::new(tokio::sync::Notify::new());
    let (plugin, connection_updates) = new_interfaces(shutdown.clone());
    let zbus_connection = Connection::system().await?;

    zbus_connection
        .object_server()
        .at(DBUS_OBJECT_PATH, plugin)
        .await?;

    zbus_connection
        .object_server()
        .at(DBUS_OBJECT_PATH, connection_updates)
        .await?;

    zbus_connection.request_name(DBUS_SERVICE_NAME).await?;

    log::info!(
        "Plugin registered at {} with service name {}",
        DBUS_OBJECT_PATH,
        DBUS_SERVICE_NAME
    );
    log::info!("Waiting for NetworkManager connections...");

    // Wait for SIGINT or SIGTERM
    let mut sigint = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::interrupt(),
    )?;
    let mut sigterm = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    )?;

    tokio::select! {
        _ = sigint.recv()       => log::info!("Received SIGINT, shutting down..."),
        _ = sigterm.recv()      => log::info!("Received SIGTERM, shutting down..."),
        _ = shutdown.notified() => log::info!("Disconnect received, shutting down..."),
    }

    Ok(())
}
