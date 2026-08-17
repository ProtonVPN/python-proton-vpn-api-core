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
//! D-Bus service exposing the kill switch.
//!
//! The service must run as root, since applying the rules needs
//! `CAP_NET_ADMIN`. It owns [`DBUS_SERVICE_NAME`] on the **system** bus and
//! serves [`DBUS_INTERFACE_NAME`] at [`DBUS_OBJECT_PATH`], with two methods:
//!
//! | method     | signature | effect                            |
//! |------------|-----------|-----------------------------------|
//! | `Enable`   | `(uss)`   | apply the kill switch rules       |
//! | `Disable`  | *(none)*  | remove the nftables table         |
//!
//! The `(uss)` argument is `fwmark`, `tunnel_iface`, `server_ip` — see
//! [`ConfigWire`], where an empty `server_ip` means "none".
//!
//! Both methods are idempotent.
//!
//! **Access is currently unrestricted** — any local user the D-Bus policy lets
//! through can enable or disable the kill switch. See the TODO in
//! `interface.rs` for the authorization models still to be decided.
//!
//! # Calling it by hand
//!
//! ```text
//! busctl call me.proton.vpn.kill_switch /me/proton/vpn/kill_switch \
//!     me.proton.vpn.kill_switch Enable '(uss)' 245447468 proton0 ''
//!
//! busctl call me.proton.vpn.kill_switch /me/proton/vpn/kill_switch \
//!     me.proton.vpn.kill_switch Disable
//! ```

mod config_wire;
mod interface;

use zbus::Connection;

pub use config_wire::ConfigWire;
pub use interface::KillSwitch;

/// Bus name the service owns on the system bus.
pub const DBUS_SERVICE_NAME: &str = "me.proton.vpn.kill_switch";

/// Object path the kill switch interface is served at.
pub const DBUS_OBJECT_PATH: &str = "/me/proton/vpn/kill_switch";

/// Interface implemented at [`DBUS_OBJECT_PATH`].
///
/// The `#[interface]` macro needs a string literal, so the name is repeated
/// there; this const is the single source of truth for runtime use.
pub const DBUS_INTERFACE_NAME: &str = "me.proton.vpn.kill_switch";

/// Serve the kill switch on the system bus until terminated.
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Starting Proton VPN kill switch service");

    let connection = Connection::system().await?;

    connection
        .object_server()
        .at(DBUS_OBJECT_PATH, KillSwitch::default())
        .await?;

    // Requested after the object is in place, so the name never resolves to a
    // service that can't yet answer.
    connection.request_name(DBUS_SERVICE_NAME).await?;

    log::info!(
        "Kill switch service registered at {DBUS_OBJECT_PATH} \
         with service name {DBUS_SERVICE_NAME}"
    );

    let mut sigint = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::interrupt(),
    )?;
    let mut sigterm = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    )?;

    tokio::select! {
        _ = sigint.recv()  => log::info!("Received SIGINT, shutting down..."),
        _ = sigterm.recv() => log::info!("Received SIGTERM, shutting down..."),
    }

    // Note: the nftables table is deliberately left in place. Stopping the
    // service must not punch a hole in the user's protection — removing the
    // rules is only ever an explicit `Disable` call.
    Ok(())
}
