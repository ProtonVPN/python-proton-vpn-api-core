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
//! The D-Bus interface served by the kill switch service.

use tokio::sync::Mutex;
use zbus::{interface, message::Header, Connection};

use super::super::config::Config;
use super::super::error::Error;
use super::super::FirewallKillSwitch;
use super::config_wire::ConfigWire;

/// The kill switch service object placed on the bus.
///
/// The mutex serializes this service's calls; nftables already applies each
/// batch atomically.
pub struct KillSwitch(Mutex<FirewallKillSwitch>);

impl Default for KillSwitch {
    fn default() -> Self {
        Self(Mutex::new(FirewallKillSwitch))
    }
}

// TODO: authorize callers. Both methods below are currently open to any local
// user that the D-Bus policy lets through, which means:
//   - any user can disable protection another user (or the VPN client) turned
//     on, defeating the point of a kill switch;
//   - any user can enable it and cut networking for the whole machine, which is
//     a local denial of service.
// The caller's uid is already resolved and logged, so adding a check needs no
// change to the method signatures. Two candidate models:
//   1. Ownership match. Record the uid that enabled it; only that uid may
//      change it afterwards. Note the two methods need *different* rules:
//      `Enable` must accept an unclaimed kill switch (owner == None) or no
//      unprivileged caller could ever enable it, while `Disable` must refuse
//      when there is no recorded owner, since the nftables table may have been
//      installed out of band by the `fwks` CLI and must not be torn down by an
//      unprivileged caller. Root should bypass both, so an administrator can
//      never be locked out.
//   2. polkit. Check a `me.proton.vpn.kill_switch.{enable,disable}` action per
//      call, which lets an unprivileged GUI be granted rights by policy and
//      optionally prompt for authentication. Needs the `zbus_polkit` crate and
//      a `.policy` file to package.
// Whichever we pick, tighten `resources/proton-vpn-kill-switch.conf` to match:
// dropping its `context="default"` rule restricts the service to root at the
// bus level, which is the cheapest option if no unprivileged caller needs it.
#[interface(name = "me.proton.vpn.kill_switch")]
impl KillSwitch {
    /// Enable the kill switch. Argument wire format: `(uss)`.
    ///
    /// Idempotent: calling it again replaces the rules already installed.
    async fn enable(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        config: ConfigWire,
    ) -> zbus::fdo::Result<()> {
        let caller = caller_uid(connection, &header).await?;

        let config = Config::try_from(config)?;
        log::info!(
            "Enabling kill switch on behalf of uid {caller} \
             (fwmark={:#x}, tunnel-iface={}, server-ip={})",
            config.fwmark,
            config.tunnel_iface,
            config
                .server_ip
                .map_or_else(|| "none".to_owned(), |ip| ip.to_string()),
        );

        self.0.lock().await.enable(&config).await?;

        Ok(())
    }

    /// Disable the kill switch, removing the nftables table.
    ///
    /// Idempotent: succeeds even when the kill switch was never enabled.
    async fn disable(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> zbus::fdo::Result<()> {
        let caller = caller_uid(connection, &header).await?;

        log::info!("Disabling kill switch on behalf of uid {caller}");

        self.0.lock().await.disable().await?;

        Ok(())
    }
}

/// Resolve the D-Bus caller's Unix uid from the message header.
///
/// The uid comes from the bus daemon rather than the message, so a caller
/// cannot claim to be somebody else.
async fn caller_uid(
    connection: &Connection,
    header: &Header<'_>,
) -> zbus::fdo::Result<u32> {
    let sender = header
        .sender()
        .ok_or(zbus::fdo::Error::Failed("message has no sender".into()))?;
    let dbus = zbus::fdo::DBusProxy::new(connection).await?;

    dbus.get_connection_unix_user(sender.to_owned().into())
        .await
}

/// Map a kill switch error onto the closest D-Bus error.
///
/// Anything the caller could have got right is reported as `InvalidArgs` so
/// they can tell a bad request from a genuine failure to apply the rules.
impl From<Error> for zbus::fdo::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::InvalidServerIp(..)
            | Error::InvalidInterfaceName(..)
            | Error::InvalidFwmark(..) => {
                zbus::fdo::Error::InvalidArgs(err.to_string())
            }
            other => zbus::fdo::Error::Failed(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_arguments_are_reported_as_invalid_args() {
        let err =
            zbus::fdo::Error::from(Error::InvalidInterfaceName(String::new()));

        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
    }

    #[test]
    fn netlink_failures_are_reported_as_failed() {
        // A caller can't fix these by sending different arguments, so they
        // must not come back as InvalidArgs.
        let err = zbus::fdo::Error::from(Error::NetlinkOpen(
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        ));

        assert!(matches!(err, zbus::fdo::Error::Failed(_)));
    }
}
