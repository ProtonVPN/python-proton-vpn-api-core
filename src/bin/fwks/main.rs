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
//! Firewall kill switch binary.
//!
//! Development tool for exercising the nftables kill switch by hand, without
//! going through the VPN client. Must run as root (netlink/netfilter access
//! required).

// A current-thread runtime is enough for the CLI, otherwise extra workers would
// sit idle.
#[cfg(feature = "kill_switch")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    use std::net::IpAddr;
    use std::process::ExitCode;

    use clap::{Parser, Subcommand};

    use proton_vpn_platform::kill_switch::{
        FirewallKillSwitch,
        parse_fwmark,
        Config,
        DEFAULT_FWMARK,
        DEFAULT_TUNNEL_IFACE,
    };

    /// fwmark-based kill switch for WireGuard VPNs.
    #[derive(Parser)]
    #[command(name = "fwks")]
    #[command(version, about, long_about = None)]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }

    #[derive(Subcommand)]
    enum Command {
        /// Enable the kill switch.
        Up {
            /// WireGuard fwmark, decimal or 0x-prefixed hex.
            /// [default: 245447468]
            #[arg(long)]
            fwmark: Option<String>,

            /// WireGuard tunnel interface name.
            #[arg(long, default_value = DEFAULT_TUNNEL_IFACE)]
            iface: String,

            /// VPN server IP. If set, traffic to it is allowed during the
            /// connecting phase; if omitted, the server-IP rule is skipped.
            #[arg(long)]
            server_ip: Option<IpAddr>,
        },
        /// Disable the kill switch (remove the nftables table).
        Down,
    }

    // The library reports what it did through the `log` facade, so mirror it
    // to stderr. RUST_LOG still wins when it is set.
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .format_target(false)
    .init();

    let mut ks = FirewallKillSwitch;

    let result = async {
        match Cli::parse().command {
            Command::Up {
                fwmark,
                iface,
                server_ip,
            } => {
                let fwmark = fwmark
                    .as_deref()
                    .map_or(Ok(DEFAULT_FWMARK), parse_fwmark)?;

                ks.enable(&Config {
                    fwmark,
                    tunnel_iface: iface,
                    server_ip,
                })
                .await
            }
            Command::Down => ks.disable().await,
        }
    }
    .await;

    if let Err(e) = result {
        // Display, not the Debug that returning Err from main would print.
        eprintln!("Error: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
