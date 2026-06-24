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
use proton_vpn_platform::protun::core::{
    Command as ProtunCommand,
    FileWriteMode,
};

#[cfg(feature = "protun")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use proton_vpn_platform::protun::nm_protun_service as protun_service;

    /// ProtonVPN NetworkManager plugin
    #[derive(Parser, Debug)]
    #[command(name = "protun")]
    #[command(version, about, long_about = None)]
    struct Args {
        #[command(subcommand)]
        command: Option<Command>,
    }

    #[derive(Subcommand, Debug)]
    enum CliCommand {
        /// Generate nmcli command from a WireGuard config file
        Nm {
            /// Path to WireGuard config file
            #[arg(long)]
            read_config: PathBuf,
        },
        /// Send settings update to the running protun service
        Protun {
            /// Protun command to run
            #[command(subcommand)]
            run: ProtunCommand,
        },
    }

    #[derive(Subcommand, Debug)]
    enum Command {
        /// CLI utilities for managing the protun service
        Cli {
            #[command(subcommand)]
            command: CliCommand,
        },
    }

    let args = Args::parse();

    match args.command {
        Some(Command::Cli { command: CliCommand::Nm { read_config, .. } }) => {
            cli::run(read_config).await
        },
        Some(Command::Cli { command: CliCommand::Protun { run } }) => {
            use proton_vpn_platform::protun::core::ConnectionManager;
            ConnectionManager::new().await?.run(run).await?;
            Ok(())
        },
        None => protun_service::run().await,
    }
}


#[cfg(not(feature = "protun"))]
fn main() {
    eprintln!("This binary requires the 'protun' feature to be enabled.");
    eprintln!("Build with: cargo build --features protun --bin protun");
    std::process::exit(1);
}
