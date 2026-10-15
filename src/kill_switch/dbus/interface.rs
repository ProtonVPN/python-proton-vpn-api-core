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

use std::fmt;

use tokio::sync::Mutex;
use zbus::message::{Header, Message};
use zbus::names::ErrorName;
use zbus::{interface, Connection};

use super::super::config::FirewallConfig;
use super::super::error::Error;
use super::super::FirewallKillSwitch;
use super::config_wire::ConfigWire;
use super::DBUS_ERROR_NOT_OWNER;

/// The kill switch service object placed on the bus.
///
/// The mutex serializes this service's calls, so the ownership check and the
/// change it guards can't interleave with another caller's; nftables already
/// applies each batch atomically.
pub struct KillSwitch(Mutex<FirewallKillSwitch>);

impl Default for KillSwitch {
    fn default() -> Self {
        Self(Mutex::new(FirewallKillSwitch::default()))
    }
}

// Every method is open to any local user the D-Bus policy lets through, but
// passes the caller's uid on: once the kill switch is installed, only the uid
// that installed it, or root, may change it. `FirewallKillSwitch` enforces
// that — see `firewall_kill_switch::ownership`.
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
    ) -> Result<(), ServiceError> {
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

        self.0.lock().await.enable(caller, &config).await?;

        Ok(())
    }

    /// Disable the kill switch, removing the nftables table.
    ///
    /// Idempotent: succeeds even when the kill switch was never enabled.
    async fn disable(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
    ) -> Result<(), ServiceError> {
        let caller = caller_uid(connection, &header).await?;

        log::info!("Disabling kill switch on behalf of uid {caller}");

        self.0.lock().await.disable(caller).await.inspect_err(|e| {
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
    ) -> Result<(), ServiceError> {
        let caller = caller_uid(connection, &header).await?;

        log::info!("Enabling IPv6 leak protection on behalf of uid {caller}");

        self.0
            .lock()
            .await
            .enable_ipv6_leak_protection(caller, &FirewallConfig::default())
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
    ) -> Result<(), ServiceError> {
        let caller = caller_uid(connection, &header).await?;

        log::info!("Disabling IPv6 leak protection on behalf of uid {caller}");

        self.0
            .lock()
            .await
            .disable_ipv6_leak_protection(caller)
            .await?;

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

/// What the methods reply with on failure: a standard D-Bus error, or
/// [`DBUS_ERROR_NOT_OWNER`] when another user owns the kill switch.
///
/// `DBusError` is implemented by hand rather than derived: the derive's
/// catch-all variant replies `org.freedesktop.zbus.Error`, which would rename
/// the standard errors (`InvalidArgs`, `Failed`, `IOError`) callers match on.
#[derive(Debug)]
pub enum ServiceError {
    Fdo(zbus::fdo::Error),
    /// The message, which names the owner's uid.
    NotOwner(String),
}

impl zbus::DBusError for ServiceError {
    fn create_reply(&self, call: &Header<'_>) -> zbus::Result<Message> {
        match self {
            Self::Fdo(err) => err.create_reply(call),
            Self::NotOwner(message) => {
                Message::error(call, self.name())?.build(message)
            }
        }
    }

    fn name(&self) -> ErrorName<'_> {
        match self {
            Self::Fdo(err) => err.name(),
            Self::NotOwner(_) => {
                ErrorName::from_static_str_unchecked(DBUS_ERROR_NOT_OWNER)
            }
        }
    }

    fn description(&self) -> Option<&str> {
        match self {
            Self::Fdo(err) => err.description(),
            Self::NotOwner(message) => Some(message),
        }
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fdo(err) => err.fmt(f),
            Self::NotOwner(message) => {
                write!(f, "{DBUS_ERROR_NOT_OWNER}: {message}")
            }
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<zbus::fdo::Error> for ServiceError {
    fn from(err: zbus::fdo::Error) -> Self {
        Self::Fdo(err)
    }
}

impl From<zbus::Error> for ServiceError {
    fn from(err: zbus::Error) -> Self {
        Self::Fdo(err.into())
    }
}

impl From<Error> for ServiceError {
    fn from(err: Error) -> Self {
        match err {
            Error::NotOwner(_) => Self::NotOwner(err.to_string()),
            other => Self::Fdo(other.into()),
        }
    }
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
            Error::State(_) => zbus::fdo::Error::Failed(message),
            // The methods reply DBUS_ERROR_NOT_OWNER instead, through
            // ServiceError; this only keeps the match exhaustive.
            Error::NotOwner(_) => zbus::fdo::Error::AccessDenied(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use zbus::DBusError;

    use super::super::super::error::{
        ConfigError, PersistenceError, RulesetError,
    };
    use super::super::super::firewall_kill_switch::ownership::NotOwner;
    use super::super::DBUS_OBJECT_PATH;
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
    fn standard_errors_keep_their_names() {
        // Callers match on these, so going through ServiceError must not
        // rename them.
        for (err, name) in [
            (
                Error::Config(ConfigError::InterfaceName(String::new())),
                "org.freedesktop.DBus.Error.InvalidArgs",
            ),
            (
                Error::Ruleset(RulesetError::NetlinkOpen(
                    std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                )),
                "org.freedesktop.DBus.Error.Failed",
            ),
            (
                Error::Persistence(PersistenceError::NotApplied(
                    "unit", "enabled",
                )),
                "org.freedesktop.DBus.Error.IOError",
            ),
        ] {
            assert_eq!(ServiceError::from(err).name().as_str(), name);
        }
    }

    #[test]
    fn not_owner_has_its_own_error_name() {
        let err = ServiceError::from(Error::NotOwner(NotOwner::OwnedBy(1000)));

        assert_eq!(
            err.name().as_str(),
            "me.proton.vpn.kill_switch.Error.NotOwner"
        );
    }

    #[test]
    fn not_owner_reply_carries_the_name_and_the_owner() {
        // The reply actually sent, not just what name() says: the client maps
        // this error name to its own exception and shows the message.
        let err = ServiceError::from(Error::NotOwner(NotOwner::OwnedBy(1000)));
        let call = Message::method_call(DBUS_OBJECT_PATH, "Disable")
            .unwrap()
            .build(&())
            .unwrap();

        let reply = err.create_reply(&call.header()).unwrap();

        assert_eq!(
            reply.header().error_name().unwrap().as_str(),
            DBUS_ERROR_NOT_OWNER
        );
        let body: String = reply.body().deserialize().unwrap();
        assert!(body.contains("uid 1000"), "{body}");
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
