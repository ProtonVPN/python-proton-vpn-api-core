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

//! Core VPN plugin types and NetworkManager D-Bus interface implementation
//!
//! This is the most important module in the protun service.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use zbus::zvariant::OwnedValue;
use zbus::{interface, object_server::SignalEmitter};

use crate::proton;

pub use super::error::*;
pub use super::settings::*;

use super::types::{Ip4Config, NMVpnServiceState, VpnConfig};

struct ConfigInfo {
    interface: InterfaceParams,
    interface_mtu: u32,
    external_gateway: std::net::IpAddr,
    dns: Vec<std::net::IpAddr>,
}

/// The internal state of our VPN plugin
#[derive(Debug)]
pub struct PluginState {
    pub service_state: NMVpnServiceState,
    pub sdk: proton::vpn::Sdk,
    /// The TUN interface name (e.g., "protun0")
    pub tun_name: Option<String>,
}

impl Default for PluginState {
    fn default() -> Self {
        Self {
            service_state: NMVpnServiceState::Init,
            sdk: proton::vpn::Sdk::new(),
            tun_name: None,
        }
    }
}

/// The main VPN Plugin D-Bus object
///
/// This implements the org.freedesktop.NetworkManager.VPN.Plugin interface
pub struct Plugin {
    pub state: Arc<RwLock<PluginState>>,
}

impl Plugin {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(PluginState::default())),
        }
    }

    /// Helper to update state and emit the StateChanged signal
    async fn set_state(
        &self,
        emitter: &SignalEmitter<'_>,
        new_state: NMVpnServiceState,
    ) -> zbus::fdo::Result<()> {
        self.state.write().await.service_state = new_state;
        Self::vpn_state_changed(emitter, new_state as u32).await?;
        Ok(())
    }

    /// Establish the VPN connection via the SDK (consumes params)
    async fn establish_connection(
        &self,
        params: ConnectionParams,
    ) -> proton::vpn::Result<ConfigInfo> {
        let ConnectionParams {
            mut interface,
            peers,
            private_key,
            dns,
            pcap_file,
        } = params;

        let external_gateway = peers[0].server_ip.0.clone(); // TODO LT: This needs to be replaced with a stub IP address.

        let mut state = self.state.write().await;
        let connection_info = state
            .sdk
            .connection_manager()
            .connect(
                proton::vpn::InitialConnectionConfig {
                    wg_private_key: proton::vpn::WgClientPrivateKey(private_key),
                    peers: peers,
                    network_available: true,
                    pcap_file,
                },
                interface.name.clone(),
            )
            .await?;

        state.tun_name = Some(connection_info.interface_name.clone());

        interface.name = connection_info.interface_name.clone(); // Update interface name in case it was changed by the SDK

        Ok(ConfigInfo {
            interface,
            interface_mtu: connection_info.mtu,
            external_gateway,
            dns,
        })
    }

    /// Emit Config and Ip4Config signals to NetworkManager
    async fn emit_nm_config(
        emitter: &SignalEmitter<'_>,
        config_info: ConfigInfo,
    ) -> zbus::fdo::Result<()> {
        fn to_u32(ip: std::net::IpAddr) -> proton::vpn::Result<u32> {
            match ip {
                std::net::IpAddr::V4(v4) => Ok(u32::from(v4).to_be()), // Network byte order
                std::net::IpAddr::V6(_) => {
                    Err(proton::vpn::Error::InvalidState(
                        "IPv6 addresses not yet supported".to_string(),
                    ))
                }
            }
        }

        Self::config(
            emitter,
            VpnConfig {
                tundev: config_info.interface.name.clone(),
                gateway: to_u32(config_info.external_gateway)?, // TODO LT: This needs to be replaced
                // with a stub IP address.
                // We will be changing the
                // external_gateway dynamically.
                has_ip4: true,
            },
        )
        .await?;

        Self::ip4_config(
            emitter,
            Ip4Config {
                address: to_u32(config_info.interface.address)?,
                prefix: config_info.interface.prefix,
                dns: config_info
                    .dns
                    .into_iter()
                    .map(to_u32)
                    .collect::<proton::vpn::Result<Vec<u32>>>()?,
                mtu: config_info.interface_mtu,
                #[cfg(feature = "protun_fwmark")]
                never_default: true,
                #[cfg(not(feature = "protun_fwmark"))]
                never_default: false,
                //ignore_auto_routes: true, // TODO LT: Do we need this as well?
            },
        )
        .await?;

        Ok(())
    }
}

/// D-Bus interface implementation for NetworkManager VPN Plugin
///
/// Interface: org.freedesktop.NetworkManager.VPN.Plugin
#[interface(name = "org.freedesktop.NetworkManager.VPN.Plugin")]
impl Plugin {
    /// Called by NetworkManager to establish a VPN connection.
    ///
    /// Check openvpn plugin, does it make additional interface
    async fn connect(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        settings: ConnectionSettings, // TODO: Check dbus api versioning.
    ) -> zbus::fdo::Result<()> {
        log::info!(
            "Connect called with sections: {:?}",
            settings.keys().collect::<Vec<_>>()
        );

        let params = load_connection_params_from_settings(settings)?;
        log::info!("Using interface name: {}", params.interface.name);

        self.set_state(&emitter, NMVpnServiceState::Starting)
            .await?;

        let config_info = self.establish_connection(params).await?;
        log::info!("TUN interface {} created", config_info.interface.name);

        Self::emit_nm_config(&emitter, config_info).await?; // TODO LT: SUpport ipv6 config
        log::info!("Sent Config and Ip4Config signals to NetworkManager");

        self.set_state(&emitter, NMVpnServiceState::Started).await?;
        log::info!("VPN connection established");

        Ok(())
    }

    /// Called by NetworkManager to establish an interactive VPN connection.
    async fn connect_interactive(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        settings: ConnectionSettings,
        _details: ConnectionSettingsSection,
    ) -> zbus::fdo::Result<()> {
        log::info!("ConnectInteractive called");
        self.connect(emitter, settings).await
    }

    /// Called by NetworkManager to check if secrets are needed before connecting.
    async fn need_secrets(
        &self,
        settings: ConnectionSettings,
    ) -> zbus::fdo::Result<String> {
        if needs_secrets(settings)? {
            log::info!("Secrets are needed for this connection");
            Ok("vpn".to_string()) // Request secrets from the "vpn" section
        } else {
            log::info!("No secrets needed for this connection");
            Ok(String::new()) // No secrets needed
        }
    }

    /// Called to provide additional secrets needed for connection.
    async fn new_secrets(
        &self,
        settings: ConnectionSettings,
    ) -> zbus::fdo::Result<()> {
        log::info!(
            "NewSecrets called with sections: {:?}",
            settings.keys().collect::<Vec<_>>()
        );
        Ok(())
    }

    /// Called by NetworkManager to disconnect the VPN.
    async fn disconnect(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        log::info!("Disconnect called");

        self.set_state(&emitter, NMVpnServiceState::Stopping)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

        {
            log::info!("Calling disconnect: waiting...");
            let mut state = self.state.write().await;
            state.sdk.connection_manager().disconnect().await;
            state.tun_name = None;
            log::info!("Calling disconnect: completed");
        }

        log::info!(
            "VPN connection stopped, TUN interface and routing cleaned up"
        );

        self.set_state(&emitter, NMVpnServiceState::Stopped).await?;
        log::info!("VPN disconnected");

        Ok(())
    }

    /// Called by NetworkManager to set generic configuration options.
    async fn set_config(
        &self,
        config: ConnectionSettings,
    ) -> zbus::fdo::Result<()> {
        log::info!("SetConfig called: {:?}", config);
        Ok(())
    }

    /// Called by NetworkManager to set IPv4 configuration.
    async fn set_ip4_config(
        &self,
        config: ConnectionSettings,
    ) -> zbus::fdo::Result<()> {
        log::info!("SetIp4Config called: {:?}", config);
        Ok(())
    }

    /// Called by NetworkManager to set IPv6 configuration.
    async fn set_ip6_config(
        &self,
        config: ConnectionSettings,
    ) -> zbus::fdo::Result<()> {
        log::info!("SetIp6Config called: {:?}", config);
        Ok(())
    }

    /// Called by NetworkManager to set a failure reason.
    async fn set_failure(&self, reason: String) -> zbus::fdo::Result<()> {
        log::error!("SetFailure called with reason: {}", reason);
        Ok(())
    }

    // ===== Properties =====

    #[zbus(property(emits_changed_signal = "false"))]
    async fn state(&self) -> u32 {
        self.state.read().await.service_state as u32
    }

    // ===== Signals =====

    #[zbus(signal, name = "StateChanged")]
    async fn vpn_state_changed(
        emitter: &SignalEmitter<'_>,
        state: u32,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn secrets_required(
        // TODO LT: Make sure this doesnt trigger a popup.
        emitter: &SignalEmitter<'_>,
        message: &str,
        secrets: Vec<String>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn config(
        emitter: &SignalEmitter<'_>,
        config: VpnConfig,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn ip4_config(
        emitter: &SignalEmitter<'_>,
        ip4config: Ip4Config,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn ip6_config(
        emitter: &SignalEmitter<'_>,
        ip6config: ConnectionSettingsSection,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn failure(
        emitter: &SignalEmitter<'_>,
        reason: u32,
    ) -> zbus::Result<()>;
}
