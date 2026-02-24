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
//! NetworkManager VPN plugin binary.
//!
//! Entry point for the protun service that integrates ProtonVPN with
//! NetworkManager via D-Bus.

#[cfg(feature = "protun")]
mod cli;

#[cfg(feature = "protun")]
use std::path::PathBuf;

#[cfg(feature = "protun")]
use clap::{Parser, Subcommand};

#[cfg(feature = "protun")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// ProtonVPN NetworkManager plugin
    #[derive(Parser, Debug)]
    #[command(name = "protun")]
    #[command(version, about, long_about = None)]
    struct Args {
        #[command(subcommand)]
        command: Option<Command>,
    }

    #[derive(Subcommand, Debug)]
    enum Command {
        /// Generate nmcli command from a WireGuard config file
        Cli {
            /// Path to WireGuard config file
            #[arg(long)]
            read_config: PathBuf,
        },
    }

    let args = Args::parse();

    match args.command {
        Some(Command::Cli { read_config }) => cli::run(read_config).await,
        None => proton_vpn_linux::services::protun::run().await,
    }
}

#[cfg(not(feature = "protun"))]
fn main() {
    eprintln!("This binary requires the 'protun' feature to be enabled.");
    eprintln!("Build with: cargo build --features protun --bin protun");
    std::process::exit(1);
}
