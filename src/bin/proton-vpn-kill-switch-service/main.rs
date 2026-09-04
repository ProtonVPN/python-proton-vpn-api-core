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
//! Kill switch D-Bus service binary.
//!
//! Owns `me.proton.vpn.kill_switch` on the system bus and applies the nftables
//! kill switch on request. Must run as root (netlink/netfilter access
//! required).

#[cfg(feature = "kill_switch")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use clap::Parser;

    /// Kill switch service.
    #[derive(Parser)]
    #[command(name = "proton-vpn-kill-switch-service")]
    #[command(version, about, long_about = None)]
    struct Cli {
        /// Apply the default kill switch rules and exit, instead of serving
        /// D-Bus. Used by the boot unit.
        #[arg(long)]
        apply_boot_rules: bool,
    }

    let cli = Cli::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    // The boot one-shot runs before dbus.service exists, so this path must
    // stay netlink-only: apply the default rules and exit, never serve the bus.
    if cli.apply_boot_rules {
        use proton_vpn_platform::kill_switch::{FirewallConfig, FirewallKillSwitch};

        let config = FirewallConfig::default();
        log::info!("Applying kill switch rules at boot ({})", config.tunnel_iface);

        return FirewallKillSwitch::default()
            .apply_rules(&config)
            .await
            .map_err(Into::into);
    }

    proton_vpn_platform::kill_switch::dbus::run().await
}
