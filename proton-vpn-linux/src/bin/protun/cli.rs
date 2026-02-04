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
//! CLI utilities for protun.

use std::path::PathBuf;

use base64::prelude::*;

use python_proton_vpn_linux::proton::vpn::wireguard_utils::WireguardConfig;

/// Generate and print nmcli command from a WireGuard config file
pub async fn run(
    config_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_str = std::fs::read_to_string(&config_path)?;
    let config = WireguardConfig::try_from(config_str.as_str())?;

    // Extract values from config
    let endpoint = config.peer.get_endpoint()?;
    let public_key = BASE64_STANDARD.encode(config.peer.get_public_key()?);
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

    // Build peers JSON with escaped commas for nmcli
    let peers_json = format!(
        r#"[{{"id": "{}"\, "endpoint": "{}"\, "public-key": "{}"}}]"#,
        peer_id, endpoint, public_key
    );

    // Print nmcli command
    println!(
        r#"nmcli connection add \
    type vpn \
    vpn-type protun \
    con-name proton0 \
    ipv4.addresses '{}/{}' \
    ipv4.dns '{}' \
    vpn.data 'peers = {}'"#,
        address,
        prefix,
        dns.join(","),
        peers_json
    );

    Ok(())
}
