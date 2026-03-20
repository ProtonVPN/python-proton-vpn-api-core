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
use proton_vpn_linux::services::protun::settings::PcapFileInfo;

#[cfg(feature = "protun")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use proton_vpn_linux::services::protun as protun_service;

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
            /// Path to pcap file path for debugging (optional)
            #[arg(long)]
            pcap_file: Option<PathBuf>,
            /// Max size of pcap file in bytes (optional, default: 10 MB)
            #[arg(long)]
            pcap_max_bytes: Option<u64>,
        },
    }

    let args = Args::parse();

    fn get_pcap_file(pcap_file: Option<PathBuf>, pcap_max_bytes: Option<u64>) -> Option<PcapFileInfo> {
        if let Some(file_path) = pcap_file {
            return Some(PcapFileInfo {
                file_path: file_path,
                max_bytes: pcap_max_bytes,
                mode: protun_service::settings::FileWriteMode::Overwrite,
            });
        }
        return None;
    }

    match args.command {
        Some(Command::Cli { read_config, pcap_file, pcap_max_bytes }) => {
            let pcap_file = get_pcap_file(pcap_file, pcap_max_bytes);

            cli::run(read_config, pcap_file).await
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
