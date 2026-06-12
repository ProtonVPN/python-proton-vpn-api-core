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

//! Core VPN plugin types and NetworkManager D-Bus interface implementation
//!
//! This is the most important module in the protun service.
use libc::{c_void, ioctl, open, O_NONBLOCK, O_RDWR};

use std::collections::HashMap;
use std::sync::Arc;

use protun::api::connection::*;

use super::netlink::NetlinkHandle;

pub use protun::api::{
    connection::{InitialConnectionConfig, PeerInfo, WgClientPrivateKey, PcapFileInfo},
    state::State,
    events::Event,
};

use tokio::sync::RwLock;
//use zbus::zvariant::OwnedValue;
//use zbus::{Connection, interface, message::Header, object_server::SignalEmitter};
pub use super::error::*;
pub use super::settings::*;

use super::types::NMVpnServiceState;

/// MTU for the VPN tunnel interface
pub const VPN_MTU: u32 = 1420;
const FWMARK: u32 = 245447468;

pub struct ConnectionInfo {
    pub interface_name: String,
    pub mtu: u32,
}

/// The internal state of our VPN plugin
pub struct Service {
    pub service_state: NMVpnServiceState,
    /// The UID of the user who owns the connection (from connection.permissions)
    pub user: Option<u32>,
    /// The active VPN connection, if any
    connection: Option<Connection>,
    // The name of the tun interface
    interface_name: String,
    ipv6: bool,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("service_state", &self.service_state)
            .field("user", &self.user)
            .field("interface_name", &self.interface_name)
            .finish()
    }
}

impl Default for Service {
    fn default() -> Self {
        Self {
            service_state: NMVpnServiceState::Init,
            user: None,
            connection: None,
            interface_name: String::new(),
            ipv6: false,
        }
    }
}

impl Service {
    /// Connect to VPN with the specified TUN interface name pattern.
    ///
    /// This async function handles:
    /// - TUN device creation
    /// - Interface configuration (UP + MTU)
    /// - WireGuard connection establishment
    ///
    /// # Arguments
    /// * `initial_config` - WireGuard configuration (private key, peers)
    /// * `tun_interface` - Interface name or pattern. Use `%d` suffix for auto-numbering
    ///   (e.g., "protun%d" becomes "protun0", "protun1", etc.)
    ///
    /// # Returns
    /// The actual interface name that was created (useful when using `%d` pattern)
    pub async fn connect(
        &mut self,
        initial_config: InitialConnectionConfig,
        tun_interface: String,
        ipv6: bool,
    ) -> Result<ConnectionInfo> {
        log::info!(
            "service: starting connection with {:?}",
            initial_config
        );

        if self.connection.is_some() {
            log::error!("service: connection attempt while already connected");
            return Err(Error::InvalidState(
                "Connection already established".to_string(),
            ));
        }

        // Create netlink handle for interface configuration
        let nl = NetlinkHandle::new()?;

        // Create TUN device
        let (tun_fd, actual_name) = create_tun(&tun_interface)?;
        self.interface_name = actual_name.clone();

        // Start the WireGuard connection
        let connection = Connection::unix_connect(
            initial_config,
            tun_fd,
            Box::new(on_state_changed),
            Some(Box::new(
                move |socket_fd: i32| {
                    if let Err(error) = set_fwmark_on_socket(socket_fd, FWMARK) {
                        log::error!("Unable to set fwmark on socket {error}");
                    }
                })),
            Box::new(on_event),
        );

        // TODO LT: Remember local agent

        // Configure interface: UP + MTU
        nl.configure_interface(&actual_name, VPN_MTU).await?;

        self.ipv6 = ipv6;

        // Configure the routing
        nl.setup_routing(FWMARK, &actual_name, ipv6).await?;

        self.connection = Some(connection);

        log::info!(
            "service: connected to VPN on interface {}",
            actual_name
        );

        Ok(ConnectionInfo {
            interface_name: actual_name,
            mtu: VPN_MTU,
        })
    }

    /// Disconnect from VPN.
    pub async fn disconnect(&mut self) {

        match NetlinkHandle::new() {
            Ok(nl) => if let Err(error) =
                nl.teardown_routing(FWMARK, &self.interface_name, self.ipv6).await
                {
                    log::error!("Failed to teardown routing: {error}");
                }
            Err(err) => {
                log::error!("Unable to connect to netlink {err}");
            }
        }

        // Tunnel
        if let Some(connection) = self.connection.take()
        {
            connection.disconnect_and_wait();

            log::info!(
                "service: disconnected and joined connection thread"
            );
        } else {
            log::error!("service: disconnect called but no active connection");
        }
    }

    pub fn update_wg_private_key(
        &mut self,
        private_key: [u8; 32],
    ) -> Result<()> {
        if let Some(connection) = &self.connection
        {
            connection.update_wg_private_key(PrivateKeyUpdateInfo {
                wg_private_key: WgClientPrivateKey(private_key),
            });
        }
        Ok(())
    }

    pub fn update_peers(&mut self, peers: Vec<PeerInfo>) -> Result<()> {
        if let Some(connection) = &self.connection
        {
            connection.update_peers(peers);
        }
        Ok(())
    }

    pub fn pcap_start(&mut self, pcap_file: PcapFileInfo) -> Result<()> {
        let connection = self.connection.as_ref()
            .ok_or_else(|| Error::InvalidState("no active VPN connection".into()))?;
        connection.start_packet_capture(pcap_file);
        Ok(())
    }

    pub fn pcap_stop(&mut self) -> Result<()> {
        let connection = self.connection.as_ref()
            .ok_or_else(|| Error::InvalidState("no active VPN connection".into()))?;
        connection.stop_packet_capture();
        Ok(())
    }
}

pub type ServiceHandle = Arc<RwLock<Service>>;


/// Create a TUN interface and return the file descriptor and actual interface name.
///
/// # Arguments
/// * `name` - Interface name or pattern. Use `%d` suffix for kernel auto-numbering
///   (e.g., "protun%d" will create "protun0", "protun1", etc.)
///
/// # Returns
/// A tuple of (file_descriptor, actual_interface_name)
fn create_tun(name: &str) -> std::io::Result<(i32, String)> {
    let tun_fd =
        unsafe { open(c"/dev/net/tun".as_ptr(), O_RDWR | O_NONBLOCK, 0) }; // nosemgrep

    if tun_fd == -1 {
        return Err(std::io::Error::last_os_error());
    }

    // TODO LT: Find a cleaner way to do this.
    // Use full ifreq struct size (40 bytes on Linux)
    // struct ifreq { char ifr_name[IFNAMSIZ=16]; union { ... } ifr_ifru; }
    let mut ifr = [0u8; 40];
    let name_bytes = name.as_bytes();
    let copy_len = std::cmp::min(name_bytes.len(), 15); // Leave room for null terminator
    ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
    const IFF_TUN: u16 = 0x0001; // This is a TUN device not TAP
    const IFF_NO_PI: u16 = 0x1000; // Don't include packet information headers
    const TUNSETIFF: u64 = 0x400454ca; // TUNSET config ioctl request
    let flags = IFF_TUN | IFF_NO_PI;
    ifr[16] = (flags & 0xff) as u8;
    ifr[17] = ((flags >> 8) & 0xff) as u8;

    let result =
        unsafe { ioctl(tun_fd, TUNSETIFF, ifr.as_mut_ptr() as *mut c_void) }; // nosemgrep

    if result == -1 {
        // nosemgrep
        unsafe {
            libc::close(tun_fd);
        }
        return Err(std::io::Error::last_os_error());
    }

    // Read back the actual interface name (kernel fills it in after ioctl)
    let actual_name = {
        let name_end = ifr[..16].iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&ifr[..name_end]).to_string()
    };

    log::info!(
        "Created TUN interface: {} (requested: {})",
        actual_name,
        name
    );

    Ok((tun_fd, actual_name))
}

/// Sets the SO_MARK on a raw socket file descriptor.
///
/// # Safety
/// The `socket_fd` must be a valid, open socket file descriptor.
/// Requires CAP_NET_ADMIN capability to succeed.
fn set_fwmark_on_socket(socket_fd: i32, mark: u32) -> Result<()> {

    if socket_fd <= 0 {
        return Err(Error::SocketFdInvalid("In set_fwmark_on_socket"));
    }

    type MarkId = libc::c_int;
    let mark_int = mark as MarkId;

    unsafe {  // nosemgrep
        let mark_ptr = &mark_int as *const MarkId as *const libc::c_void;
        let len = std::mem::size_of::<MarkId>() as libc::socklen_t;
        let res = libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            mark_ptr,
            len,
        );

        if res != 0 {
            return Err(Error::IO(std::io::Error::last_os_error()))
        }
    }

    Ok(())
}

fn on_state_changed(state: State) {
    log::info!("Connection state changed: {:?}", state);
}

fn on_event(event: Event) {
    log::info!("Connection event: {:?}", event);
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.disconnect_and_wait();
        }
    }
}
