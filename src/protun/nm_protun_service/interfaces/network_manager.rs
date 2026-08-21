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

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use zbus::zvariant::OwnedValue;
use zbus::{Connection, interface, message::Header, object_server::SignalEmitter};

pub use super::super::error::*;
pub use super::super::settings::*;
use super::super::service::{
    Service, ServiceHandle, WgClientPrivateKey, InitialConnectionConfig,
    ConnectionMode, SniStrategy
};

use super::super::types::{Ip4Config, Ip6Config, NMVpnServiceState, VpnConfig};
use super::super::error::{Error, Result};

// Network Manager (version 1.46.0) requires a vpn plugin to communicate the
// ip address of the vpn server (the gateway) we are connecting to, in order to
// create a direct route to it for vpn encrypted traffic.
//
// This is not something the protun plugin can provide because:
//  - There is no one server, there are a set of servers any of which the plugin
//    can choose to connect to. The plugin can also switch between servers
//    midway through a connection, or even connect to multiple servers at once.
//  - Protun is a wireguard based protocol, encrypted packets are tagged
//    with an fwmark which is used to filter what goes directly to the
//    network card and what goes through the tunnel device. A direct route in
//    the main table would undermine this, as it would be more specific than
//    the fwmark route.
//  - Packets that are explicitly not destined for the tunnel (split tunneling)
//    also use the fwmark, a direct route in the main table adds confusion.
//
// Finally, the fwmark routing rule and routing table already fix the routing
// loop issue that the Network Manager is trying to resolve by adding this
// direct route.
//
// Unfortunately, if a plugin omits a gateway ip address when signalling a
// successful startup the Network Manager will assume the plugin has failed
// to connect, and will close it down.
//
// To work around this design limitation the protun plugin signals an invalid
// gateway ip, TEST-NET-1 (192.0.2.0), this is reserved for documentation
// (as per RFC 5737), packets destined for this address are likely to be
// dropped at network boundries.
//
// Additionaly, the protun plugin adds it's own routing rules to support the
// fwmark (as mentioned above). This has the desirable side effect of suppressing
// the automatic creation of the gateway route. The reason is that the
// Network Manager checks the existing route for the gateway ip before adding
// the direct one, and it requires that the existing route:
//
//  - Is in the main routing table.
//  - Is routed to the parent network device of the tunnel (normally the network card).
//
// Both of these checks are false, as the custom routing setup by protun follows
// the wireguard convention of:
//
//  - Routing all unmarked packets in a custom table (table $fwmark)
//  - Routing all unmarked packets to the tunnel device.
//
// Finally the Network Manager has an option to disable creation of the direct
// route to the gateway: `auto-route-ext-gw no`
//
// This should be set as an extra safety measure to ensure the Network Manager
// never tries to make the route. The `nm-protun-service cli` already does this
// when creating a connection profile using nmcli.
//
// Ultimately these three strategies:
//  - our custom routing rules
//  - an invalid gateway address
//  - ipv4.auto-route-ext-gw no
//
// Ensure that the gateway routing rule isn't created, and if it ever was
// that it would be harmless.
//
//
//
// TEST-NET-1 from RFC 5737 is '192.0.2.0'
//
const NOOP_GATEWAY_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(192,0,2,0);

struct ConfigInfo {
    interface_mtu: u32,
    ipv4_interface: InterfaceParams<std::net::Ipv4Addr>,
    ipv6_interface: Option<InterfaceParams<std::net::Ipv6Addr>>,
}

/// The main VPN Plugin D-Bus object
///
/// This implements the org.freedesktop.NetworkManager.VPN.Plugin interface
pub struct NetworkManager {
    pub service: ServiceHandle,
    shutdown: std::sync::Arc<tokio::sync::Notify>,
}

impl NetworkManager {
    pub fn new(service: ServiceHandle, shutdown: std::sync::Arc<tokio::sync::Notify>) -> Self {
        Self {
            service,
            shutdown,
        }
    }

    /// Helper to update state and emit the StateChanged signal
    async fn set_state(
        &self,
        emitter: &SignalEmitter<'_>,
        new_state: NMVpnServiceState,
    ) -> zbus::fdo::Result<()> {
        self.service.write().await.service_state = new_state;
        Self::vpn_state_changed(emitter, new_state as u32).await?;
        Ok(())
    }

    /// Establish the VPN connection via the SDK (consumes params)
    async fn establish_connection(
        &self,
        params: ConnectionParams,
    ) -> Result<ConfigInfo> {
        let ConnectionParams {
            mut ipv4_interface,
            mut ipv6_interface,
            peers,
            private_key,
            user,
        } = params;

        let mut service = self.service.write().await;
        service.user = Some(user);
        let connection_info = service
            .connect(
                InitialConnectionConfig {
                    peers: peers,
                    network_available: true,
                    pcap_file : None,
                    connection_mode: ConnectionMode::NoLocalAgent {
                        wg_private_key: WgClientPrivateKey(private_key)
                    },
                    sni_strategy: SniStrategy::Random
                },
                ipv4_interface.name.clone(),
                ipv6_interface.is_some(),
            )
            .await?;

        // Update interface name in case it was changed by the SDK
        ipv4_interface.name = connection_info.interface_name.clone();
        if let Some(ipv6_interface) = & mut ipv6_interface {
            ipv6_interface.name = connection_info.interface_name.clone();
        }

        Ok(ConfigInfo {
            interface_mtu: connection_info.mtu,
            ipv4_interface,
            ipv6_interface,
        })
    }

    /// Emit Config and Ip4Config signals to NetworkManager
    async fn emit_nm_config(
        emitter: &SignalEmitter<'_>,
        config_info: ConfigInfo,
    ) -> zbus::fdo::Result<()> {
        fn to_u32(ip: std::net::Ipv4Addr) -> Result<u32> {
            Ok(u32::from(ip).to_be()) // Network byte order
        }

        Self::config(
            emitter,
            VpnConfig {
                tundev: config_info.ipv4_interface.name.clone(),
                gateway: to_u32(NOOP_GATEWAY_IP)?,
                has_ip4: true,
                has_ip6: config_info.ipv6_interface.is_some(),
            },
        )
        .await?;

        Self::ip4_config(
            emitter,
            Ip4Config {
                address: to_u32(config_info.ipv4_interface.address)?,
                prefix: config_info.ipv4_interface.prefix,
                dns: config_info
                    .ipv4_interface
                    .dns
                    .into_iter()
                    .map(to_u32)
                    .collect::<Result<Vec<u32>>>()?,
                mtu: config_info.interface_mtu,
                never_default: true,
                ignore_auto_routes: true,
            },
        )
        .await?;

        if let Some(ipv6) = config_info.ipv6_interface {
            Self::ip6_config(emitter, Ip6Config {
                address: ipv6.address.octets().to_vec(),
                prefix: ipv6.prefix,
                dns: ipv6.dns
                    .iter()
                    .map(|ip| ip.octets().to_vec())
                    .collect(),
                never_default: true,
            }).await?;
        }

        Ok(())
    }
}

/// D-Bus interface implementation for NetworkManager VPN Plugin
///
/// Interface: org.freedesktop.NetworkManager.VPN.Plugin
#[interface(name = "org.freedesktop.NetworkManager.VPN.Plugin")]
impl NetworkManager {
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
        log::info!("Using interface name: {}", params.ipv4_interface.name);

        self.set_state(&emitter, NMVpnServiceState::Starting)
            .await?;

        let config_info = self.establish_connection(params).await?;
        log::info!("TUN interface {} created", config_info.ipv4_interface.name);

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
            let mut state = self.service.write().await;
            state.disconnect().await;
            log::info!("Calling disconnect: completed");
        }

        log::info!(
            "VPN connection stopped, TUN interface and routing cleaned up"
        );

        self.set_state(&emitter, NMVpnServiceState::Stopped).await?;
        log::info!("VPN disconnected");

        log::info!("Service shutting down");

        self.shutdown.notify_one();

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
        self.service.read().await.service_state as u32
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
        ip6config: Ip6Config,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn failure(
        emitter: &SignalEmitter<'_>,
        reason: u32,
    ) -> zbus::Result<()>;
}
