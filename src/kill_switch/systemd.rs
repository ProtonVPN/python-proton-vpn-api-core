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
//! The boot unit that re-applies the kill switch after a reboot.
//!
//! Permanent mode has no state file: this unit's *enablement* is the setting.

use async_trait::async_trait;
use zbus::{proxy, Connection};

use super::error::{PersistenceError, Result};

/// The one-shot that applies the default ruleset at boot.
pub const BOOT_UNIT: &str = "proton-vpn-kill-switch-boot.service";

/// Turning boot persistence on and off. A trait so the kill switch can be
/// tested without a system bus; production uses [`SystemdBootUnit`].
#[async_trait]
pub trait BootUnit: Send + Sync {
    async fn enable(&self) -> Result<()>;
    async fn disable(&self) -> Result<()>;
}

/// Only the two calls we need out of `org.freedesktop.systemd1.Manager`.
#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
trait SystemdUnitFiles {
    /// `runtime = false` writes the symlink under /etc so it survives a
    /// reboot, which is the entire point.
    fn enable_unit_files(
        &self,
        files: &[&str],
        runtime: bool,
        force: bool,
    ) -> zbus::Result<(bool, Vec<(String, String, String)>)>;

    fn disable_unit_files(
        &self,
        files: &[&str],
        runtime: bool,
    ) -> zbus::Result<Vec<(String, String, String)>>;

    fn get_unit_file_state(&self, file: &str) -> zbus::Result<String>;
}

/// [`BootUnit`] backed by systemd on the system bus. Runs as root, so no
/// polkit. Connects per call so that constructing it never touches the bus.
#[derive(Default)]
pub struct SystemdBootUnit;

impl SystemdBootUnit {
    async fn set(&self, enabled: bool) -> Result<()> {
        let wanted = if enabled { "enabled" } else { "disabled" };
        let failed = |e: zbus::Error| {
            if enabled {
                PersistenceError::Enable(BOOT_UNIT, e)
            } else {
                PersistenceError::Disable(BOOT_UNIT, e)
            }
        };

        let connection = Connection::system().await.map_err(failed)?;
        let proxy = SystemdUnitFilesProxy::new(&connection)
            .await
            .map_err(failed)?;

        // The kill switch is re-enabled on every connection state change, so
        // the usual call asks for the state it is already in. This sits on the
        // connect path, so keep it a read.
        if is_enabled(&proxy).await.map_err(failed)? == enabled {
            return Ok(());
        }

        if enabled {
            // force: replace a symlink left pointing somewhere stale rather
            // than failing.
            let runtime = false;
            let force = true;
            proxy
                .enable_unit_files(&[BOOT_UNIT], runtime, force)
                .await
                .map_err(failed)?;
        } else {
            let runtime = false;
            proxy
                .disable_unit_files(&[BOOT_UNIT], runtime)
                .await
                .map_err(failed)?;
        }

        // systemd answers OK even when it linked nothing, e.g. for a unit with
        // no [Install] section, so read the state back rather than trust the
        // reply.
        if is_enabled(&proxy).await.map_err(failed)? != enabled {
            return Err(PersistenceError::NotApplied(BOOT_UNIT, wanted).into());
        }

        // No Manager.Reload: only the next boot reads the symlink, and it is
        // slow enough to be worth not failing the call over.
        Ok(())
    }
}

/// Whether the boot unit is currently enabled. A missing unit file counts as
/// disabled, so turning it off on a machine without the package is a no-op.
async fn is_enabled(proxy: &SystemdUnitFilesProxy<'_>) -> zbus::Result<bool> {
    match proxy.get_unit_file_state(BOOT_UNIT).await {
        Ok(state) => Ok(state == "enabled"),
        Err(zbus::Error::MethodError(..)) => Ok(false),
        Err(other) => Err(other),
    }
}

#[async_trait]
impl BootUnit for SystemdBootUnit {
    async fn enable(&self) -> Result<()> {
        self.set(true).await.inspect_err(|e| log::error!("{e}"))?;
        log::info!("Boot unit {BOOT_UNIT} enabled");
        Ok(())
    }

    async fn disable(&self) -> Result<()> {
        self.set(false).await.inspect_err(|e| log::error!("{e}"))?;
        log::info!("Boot unit {BOOT_UNIT} disabled");
        Ok(())
    }
}
