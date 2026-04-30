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
//! CLI utilities for protun.

use std::path::PathBuf;

use base64::prelude::*;

use proton_vpn_linux::protun::nm_protun_service::wireguard_utils::WireguardConfig;
use proton_vpn_linux::protun::nm_protun_service as protun_service;
use proton_vpn_linux::protun::core::PeerInfo;

/// Generate and print nmcli command from a WireGuard config file
pub async fn run(config_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let config_str = std::fs::read_to_string(&config_path)?;
    let config = WireguardConfig::try_from(config_str.as_str())?;

    // Extract values from config
    let endpoint = config.peer.get_endpoint()?;
    let public_key = BASE64_STANDARD.encode(config.peer.get_public_key()?);
    let private_key = BASE64_STANDARD.encode(config.interface.get_private_key()?);
    let (address, prefix) = config.interface.get_address_and_prefix()?;
    let dns: Vec<String> = config
        .interface
        .get_dns_servers()
        .iter()
        .map(|ip| ip.to_string())
        .collect();

    // Use config filename as peer id
    let peer_id = config_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "peer0".to_string());

    use protun_service::settings::ProtunSetting as _;
    use protun_service::settings::SETTINGS_KEY;

    let dns = dns.join(",");

    let settings_str = protun_service::settings::Settings {
        version : protun_service::settings::VERSION,
        peers : vec![PeerInfo {
                        id: peer_id,
                        endpoint: endpoint.ip().to_string(),
                        public_key,
                        udp_ports: vec![endpoint.port()],
                        tcp_ports: vec![],
                        tls_ports: vec![],
                        priority: 0,
                    }],
    }.to_settings_string()?;

    let username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .map_err(|_| "cannot determine current user (USER/LOGNAME not set)")?;

    // Print nmcli command
    println!(
        r#"
            nmcli connection add \
            type vpn \
            vpn-type protun \
            con-name proton0 \
            connection.permissions 'user:{username}' \
            ipv4.addresses '{address}/{prefix}' \
            ipv4.dns '{dns}' \
            vpn.data 'private-key-flags=1' \
            +vpn.data '{SETTINGS_KEY} = {settings_str}' \
            vpn.secrets 'private-key = {private_key}'
        "#
    );

    Ok(())
}
