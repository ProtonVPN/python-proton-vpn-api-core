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

use super::super::config::FirewallConfig;
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
        Self(Mutex::new(FirewallKillSwitch::default()))
    }
}

// TODO: authorize callers. Every method below is currently open to any local
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
    /// Enable the kill switch. Argument wire format: `(ussb)`.
    ///
    /// When `permanent` is set this also enables the boot unit, so the rules
    /// come back after a reboot; when it is clear the boot unit is disabled.
    ///
    /// Idempotent: calling it again replaces the rules already installed.
    async fn enable(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        config: ConfigWire,
    ) -> zbus::fdo::Result<()> {
        let caller = caller_uid(connection, &header).await?;

        let config = FirewallConfig::try_from(config)?;
        log::info!(
            "Enabling kill switch on behalf of uid {caller} \
             (fwmark={:#x}, tunnel-iface={}, server-ip={}, permanent={})",
            config.fwmark,
            config.tunnel_iface,
            config
                .server_ip
                .map_or_else(|| "none".to_owned(), |ip| ip.to_string()),
            config.permanent,
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

        self.0.lock().await.disable().await.inspect_err(|e| {
            log::error!("Disabling the kill switch failed: {e}");
        })?;

        Ok(())
    }

    /// Enable IPv6 leak protection, blocking IPv6 that is not going through the
    /// tunnel and leaving IPv4 alone.
    ///
    /// Takes no arguments: the fwmark and tunnel interface come from the
    /// service's own defaults, so callers do not have to carry those constants.
    ///
    /// Independent of [`enable`](Self::enable) — the client asks for this when
    /// the kill switch is off, so it outlives `Disable`.
    ///
    /// Idempotent: calling it again replaces the rules already installed.
    async fn enable_ipv6_leak_protection(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> zbus::fdo::Result<()> {
        let caller = caller_uid(connection, &header).await?;

        log::info!("Enabling IPv6 leak protection on behalf of uid {caller}");

        self.0
            .lock()
            .await
            .enable_ipv6_leak_protection(&FirewallConfig::default())
            .await?;

        Ok(())
    }

    /// Disable IPv6 leak protection, leaving the kill switch table alone.
    ///
    /// Idempotent: succeeds even when it was never enabled.
    async fn disable_ipv6_leak_protection(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> zbus::fdo::Result<()> {
        let caller = caller_uid(connection, &header).await?;

        log::info!("Disabling IPv6 leak protection on behalf of uid {caller}");

        self.0.lock().await.disable_ipv6_leak_protection().await?;

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
        let message = err.to_string();

        match err {
            // Anything the caller could have got right, so they can tell a bad
            // request from a genuine failure to apply the rules.
            Error::Config(_) => zbus::fdo::Error::InvalidArgs(message),
            Error::Ruleset(_) => zbus::fdo::Error::Failed(message),
            // Not Failed: the rules *are* up, only their persistence is not,
            // which is a different thing for the caller to decide about.
            Error::Persistence(_) => zbus::fdo::Error::IOError(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::error::{
        ConfigError, PersistenceError, RulesetError,
    };
    use super::*;

    #[test]
    fn bad_arguments_are_reported_as_invalid_args() {
        let err = zbus::fdo::Error::from(Error::Config(
            ConfigError::InterfaceName(String::new()),
        ));

        assert!(matches!(err, zbus::fdo::Error::InvalidArgs(_)));
    }

    #[test]
    fn netlink_failures_are_reported_as_failed() {
        // A caller can't fix these by sending different arguments, so they
        // must not come back as InvalidArgs.
        let err =
            zbus::fdo::Error::from(Error::Ruleset(RulesetError::NetlinkOpen(
                std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            )));

        assert!(matches!(err, zbus::fdo::Error::Failed(_)));
    }

    #[test]
    fn persistence_failures_are_not_reported_as_plain_failures() {
        // The rules are up; only the reboot half failed. Reporting it the same
        // way as "nothing was applied" would lose that distinction.
        let err = zbus::fdo::Error::from(Error::Persistence(
            PersistenceError::Enable("unit", zbus::Error::InvalidReply),
        ));

        assert!(matches!(err, zbus::fdo::Error::IOError(_)));
    }

    #[test]
    fn method_names_are_stable() {
        // zbus derives these from the Rust function names, so renaming a method
        // silently renames the D-Bus API. Callers in other languages hardcode
        // them, so pin them here.
        use zbus::object_server::Interface;

        let mut xml = String::new();
        KillSwitch::default().introspect_to_writer(&mut xml, 0);

        for method in [
            "Enable",
            "Disable",
            "EnableIpv6LeakProtection",
            "DisableIpv6LeakProtection",
        ] {
            assert!(
                xml.contains(&format!("name=\"{method}\"")),
                "{method} missing from introspection XML:\n{xml}"
            );
        }
    }
}
