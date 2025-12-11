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

use super::helpers::{load_connection_params, ConnectionParams};
use super::types::{
    Ip4Config, NMConnectionSettings, NMVpnServiceState, VpnConfig,
};

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
    ) -> proton::vpn::Result<proton::vpn::ConnectionInfo> {
        let mut state = self.state.write().await;
        let connection_info = state
            .sdk
            .connection_manager()
            .connect(
                proton::vpn::InitialConnectionConfig {
                    wg_private_key: proton::vpn::WgClientPrivateKey(
                        params.wg_config.interface.get_private_key()?,
                    ),
                    peers: vec![params.peer_info],
                    network_available: true,
                    capture_packet: None,
                },
                params.interface_name,
            )
            .await?;

        state.tun_name = Some(connection_info.interface_name.clone());
        Ok(connection_info)
    }

    /// Emit Config and Ip4Config signals to NetworkManager
    async fn emit_nm_config(
        emitter: &SignalEmitter<'_>,
        connection_info: &proton::vpn::ConnectionInfo,
        (external_gateway, internal_address, prefix, dns): (
            u32,
            u32,
            u8,
            Vec<u32>,
        ),
    ) -> zbus::fdo::Result<()> {
        Self::config(
            emitter,
            VpnConfig {
                tundev: connection_info.interface_name.clone(),
                gateway: external_gateway, // TODO LT: This needs to be replaced
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
                address: internal_address,
                prefix,
                dns,
                mtu: connection_info.mtu,
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
        settings: NMConnectionSettings, // TODO: Check dbus api versioning.
    ) -> zbus::fdo::Result<()> {
        log::info!(
            "Connect called with sections: {:?}",
            settings.keys().collect::<Vec<_>>()
        );

        let params = load_connection_params(&settings)?;
        log::info!("Using interface name: {}", params.interface_name);

        // Extract NM config values before consuming params
        let nm_config = (
            params.external_gateway,
            params.internal_address,
            params.prefix,
            params.dns.clone(),
        );

        self.set_state(&emitter, NMVpnServiceState::Starting)
            .await?;

        let connection_info = self.establish_connection(params).await?;
        log::info!("TUN interface {} created", connection_info.interface_name);

        Self::emit_nm_config(&emitter, &connection_info, nm_config).await?; // TODO LT: SUpport ipv6 config
        log::info!("Sent Config and Ip4Config signals to NetworkManager");

        self.set_state(&emitter, NMVpnServiceState::Started).await?;
        log::info!("VPN connection established");

        Ok(())
    }

    /// Called by NetworkManager to establish an interactive VPN connection.
    async fn connect_interactive(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        settings: NMConnectionSettings,
        _details: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        log::info!("ConnectInteractive called");
        self.connect(emitter, settings).await
    }

    /// Called by NetworkManager to check if secrets are needed before connecting.
    async fn need_secrets(
        &self,
        settings: NMConnectionSettings,
    ) -> zbus::fdo::Result<String> {
        log::info!(
            "NeedSecrets called with sections: {:?}",
            settings.keys().collect::<Vec<_>>()
        );
        Ok(String::new())
    }

    /// Called to provide additional secrets needed for connection.
    async fn new_secrets(
        &self,
        settings: NMConnectionSettings,
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
        config: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        log::info!("SetConfig called: {:?}", config);
        Ok(())
    }

    /// Called by NetworkManager to set IPv4 configuration.
    async fn set_ip4_config(
        &self,
        config: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        log::info!("SetIp4Config called: {:?}", config);
        Ok(())
    }

    /// Called by NetworkManager to set IPv6 configuration.
    async fn set_ip6_config(
        &self,
        config: HashMap<String, OwnedValue>,
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
        ip6config: HashMap<String, OwnedValue>,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn failure(
        emitter: &SignalEmitter<'_>,
        reason: u32,
    ) -> zbus::Result<()>;
}
