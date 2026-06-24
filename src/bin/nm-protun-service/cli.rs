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

use proton_vpn_platform::protun::nm_protun_service::wireguard_utils::WireguardConfig;
use proton_vpn_platform::protun::nm_protun_service as protun_service;
use proton_vpn_platform::protun::core::PeerInfo;

/// Generate and print nmcli command from a WireGuard config file
pub async fn config_to_nmcli(username: &str,
                             con_name: String,
                             config: WireguardConfig) -> Result<String, Box<dyn std::error::Error>> {

    // Extract values from config
    let endpoint = config.peer.get_endpoint()?;
    let public_key = BASE64_STANDARD.encode(config.peer.get_public_key()?);
    let private_key = BASE64_STANDARD.encode(config.interface.get_private_key()?);
    let ((address, prefix), ipv6) = config.interface.get_addresses_and_prefix()?;
    let all_dns = config.interface.get_dns_servers();
    let ipv4_dns = all_dns.iter()
        .filter(|ip| ip.is_ipv4())
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let ipv6_dns = all_dns.iter()
        .filter(|ip| ip.is_ipv6())
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>();

    use protun_service::settings::ProtunSetting as _;
    use protun_service::settings::SETTINGS_KEY;

    let settings_str = protun_service::settings::Settings {
        version : protun_service::settings::VERSION,
        peers : vec![PeerInfo {
                        id: con_name.clone(),
                        endpoint: endpoint.ip().to_string(),
                        public_key,
                        udp_ports: vec![endpoint.port()],
                        tcp_ports: vec![],
                        tls_ports: vec![],
                        priority: 0,
                    }],
    }.to_settings_string()?;

    let ipv6 = match ipv6 {
        Some((addr, prefix)) => {
            let ipv6 = ipv6_dns.join(",");
            if ipv6.is_empty()
            {
                format!(
r#"ipv6.method manual \
    ipv6.addresses '{addr}/{prefix}' \
    ipv6.auto-route-ext-gw no \"#)
            }
            else
            {
                format!(
r#"ipv6.method manual \
    ipv6.addresses '{addr}/{prefix}' \
    ipv6.dns '{ipv6}' \
    ipv6.auto-route-ext-gw no \"#)
            }
        }
        None => "\\".to_string(),
    };

    Ok(
        format!(
r#"
nmcli connection add \
    type vpn \
    vpn-type protun \
    con-name {con_name} \
    connection.permissions 'user:{username}' \
    {ipv6}
    ipv4.method manual \
    ipv4.addresses '{address}/{prefix}' \
    ipv4.auto-route-ext-gw no \
    ipv4.dns '{ipv4_dns}' \
    vpn.data 'private-key-flags=1' \
    +vpn.data '{SETTINGS_KEY} = {settings_str}' \
    vpn.secrets 'private-key = {private_key}'
"#
        )
    )
}

/// Generate and print nmcli command from a WireGuard config file
pub async fn run(config_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let config = WireguardConfig::try_from(
        std::fs::read_to_string(&config_path)?.as_str()
    )?;

    let mut con_name : String = config_path.file_name()
        .map(
            |name| {
                let mut name = PathBuf::from(name);
                name.set_extension("");
                name.display().to_string()
            }
        )
        .unwrap_or("proton0".to_string());

    let username = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .map_err(|_| "cannot determine current user (USER/LOGNAME not set)")?;

    println!("{}", config_to_nmcli(&username, con_name, config).await?);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn make_config(address: &str, dns: &str) -> WireguardConfig {
        WireguardConfig::try_from(format!(r#"
[Interface]
PrivateKey = {TEST_KEY}
Address = {address}
DNS = {dns}

[Peer]
PublicKey = {TEST_KEY}
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:51820
"#).as_str()).unwrap()
    }

    #[tokio::test]
    async fn test_ipv4_and_ipv6_with_dns() {
        let config = make_config("10.0.0.1/24, fd00::1/128", "8.8.8.8, 2001:4860:4860::8888");
        let output = config_to_nmcli("test_user",
                                     "proton0".to_string(),
                                     config).await.unwrap();

        assert!(output.contains("con-name proton0"));
        assert!(output.contains("ipv4.addresses '10.0.0.1/24'"));
        assert!(output.contains("ipv4.dns '8.8.8.8'"));
        assert!(output.contains("ipv6.method manual"));
        assert!(output.contains("ipv6.addresses 'fd00::1/128'"));
        assert!(output.contains("ipv6.dns '2001:4860:4860::8888'"));
    }

    #[tokio::test]
    async fn test_ipv4_and_ipv6_without_ipv6_dns() {
        let config = make_config("10.0.0.1/24, fd00::1/128", "8.8.8.8");
        let output = config_to_nmcli("test_user",
                                     "proton0".to_string(),
                                     config).await.unwrap();

        assert!(output.contains("ipv6.method manual"));
        assert!(output.contains("ipv6.addresses 'fd00::1/128'"));
        assert!(!output.contains("ipv6.dns"));
    }

    #[tokio::test]
    async fn test_ipv4_only() {
        let config = make_config("10.0.0.1/24", "8.8.8.8");
        let output = config_to_nmcli("test_user",
                                     "proton0".to_string(),
                                     config).await.unwrap();

        assert!(output.contains("ipv4.addresses '10.0.0.1/24'"));
        assert!(!output.contains("ipv6.method"));
    }
}