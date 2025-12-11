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
//! VPN connection lifecycle management.
//!
//! Handles TUN device creation, WireGuard tunnel setup, and connection
//! state transitions.

use libc::{c_void, ioctl, open, O_NONBLOCK, O_RDWR};
use std::thread::JoinHandle;

use crate::proton::vpn::netlink::NetlinkHandle;
use crate::proton::vpn::*;

use protun::api::connection::*;

pub use protun::api::{
    connection::{InitialConnectionConfig, PeerInfo, WgClientPrivateKey},
    state::State,
};

/// MTU for the VPN tunnel interface
pub const VPN_MTU: u32 = 1420;

pub struct ConnectionInfo {
    pub interface_name: String,
    pub mtu: u32,
}

struct ConnectionHandle {
    pub connection: Connection,
    pub thread: JoinHandle<()>,
}

impl From<(Connection, JoinHandle<()>)> for ConnectionHandle {
    fn from(src: (Connection, JoinHandle<()>)) -> Self {
        let (connection, thread) = src;
        ConnectionHandle { connection, thread }
    }
}

pub struct ConnectionManager {
    connection: Option<ConnectionHandle>,
}

impl std::fmt::Debug for ConnectionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionManager")
            .field("connection", &self.connection.is_some())
            .finish()
    }
}

impl ConnectionManager {
    pub(super) fn new() -> Self {
        ConnectionManager { connection: None }
    }

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
    ) -> Result<ConnectionInfo> {
        log::info!("connection_manager: starting connection to VPN");

        if self.connection.is_some() {
            log::error!("connection_manager: connection attempt while already connected");
            return Err(Error::InvalidState(
                "Connection already established".to_string(),
            ));
        }

        // Create netlink handle for interface configuration
        let nl = NetlinkHandle::new()?;

        // Create TUN device
        let (tun_fd, actual_name) = create_tun(&tun_interface)?;

        // Start the WireGuard connection
        let (connection, thread) = Connection::connect_with_fd(
            initial_config,
            tun_fd,
            Box::new(on_state_changed),
            None,
        );

        // TODO LT: Remember local agent

        // Configure interface: UP + MTU
        nl.configure_interface(&actual_name, VPN_MTU).await?;

        self.connection = Some(ConnectionHandle { connection, thread });

        log::info!(
            "connection_manager: connected to VPN on interface {}",
            actual_name
        );

        Ok(ConnectionInfo {
            interface_name: actual_name,
            mtu: VPN_MTU,
        })
    }

    /// Disconnect from VPN.
    pub async fn disconnect(&mut self) {
        if let Some(ConnectionHandle { connection, thread }) =
            self.connection.take()
        {
            connection.disconnect();
            let _ = thread.join();
            log::info!(
                "connection_manager: disconnected and joined connection thread"
            );
        } else {
            log::info!("connection_manager: disconnect called but no active connection");
        }
    }

    pub fn update_wg_private_key(
        &mut self,
        private_key: [u8; 32],
    ) -> Result<()> {
        if let Some(ConnectionHandle {
            connection,
            thread: _,
        }) = &self.connection
        {
            connection.update_wg_private_key(PrivateKeyUpdateInfo {
                wg_private_key: WgClientPrivateKey(private_key),
            });
        }
        Ok(())
    }

    pub fn update_peers(&mut self, peers: Vec<PeerInfo>) -> Result<()> {
        if let Some(ConnectionHandle {
            connection,
            thread: _,
        }) = &self.connection
        {
            connection.update_peers(peers);
        }
        Ok(())
    }
}

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
        unsafe { open(c"/dev/net/tun".as_ptr(), O_RDWR | O_NONBLOCK, 0) };

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
        unsafe { ioctl(tun_fd, TUNSETIFF, ifr.as_mut_ptr() as *mut c_void) };

    if result == -1 {
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

fn on_state_changed(state: State) {
    log::info!("Connection state changed: {:?}", state);
}

impl Drop for ConnectionManager {
    fn drop(&mut self) {
        if let Some(ConnectionHandle { connection, thread }) =
            self.connection.take()
        {
            connection.disconnect();
            let _ = thread.join();
        }
    }
}
