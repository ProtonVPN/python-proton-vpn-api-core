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
use super::super::super::core::{Command, PcapStart};
use super::super::service::{Service, ServiceHandle};

use super::super::types::{Ip4Config, NMVpnServiceState, VpnConfig};


/// Resolve the D-Bus caller's Unix UID from the message header.
async fn caller_uid(
    connection: &Connection,
    header: &Header<'_>,
) -> zbus::fdo::Result<u32> {
    let sender = header.sender().ok_or(zbus::fdo::Error::Failed("message has no sender".into()))?;
    let dbus = zbus::fdo::DBusProxy::new(connection).await?;
    Ok(dbus.get_connection_unix_user(sender.to_owned().into()).await?)
}

fn check_access(caller: u32, owner: u32) -> zbus::fdo::Result<()> {
    if caller != owner {
        return Err(zbus::fdo::Error::AccessDenied(format!(
            "caller uid {caller:?} is not the connection owner"
        )));
    }
    Ok(())
}

/// Check that the D-Bus caller is the connection owner stored in state.
async fn check_caller_is_connection_owner(
    connection: &Connection,
    header: &Header<'_>,
    state: &ServiceHandle,
) -> zbus::fdo::Result<()> {
    let caller = caller_uid(connection, header).await?;
    log::info!("Received command from caller: {:?}, resolved uid: {:?}", header.sender(), caller);
    let owner = state.read().await.user.clone()
        .ok_or(zbus::fdo::Error::AccessDenied("no connection owner set".into()))?;
    if let Err(e) = check_access(caller, owner) {
        log::warn!("Access denied for caller uid {caller:?}: {e}");
        return Err(e);
    }
    Ok(())
}

pub struct Protun {
    service: ServiceHandle,
}

impl Protun {
    pub fn new(service: ServiceHandle) -> Self {
        Self {
            service,
        }
    }
}

#[interface(name = "me.proton.vpn.protun")]
impl Protun {
    async fn run(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        command: Command,
    ) -> zbus::fdo::Result<()> {
        check_caller_is_connection_owner(connection, &header, &self.service).await?;

        match command {
            Command::PcapStart(pcap_start) => {
                log::info!("Received command: Start PCAP recording with max size {:?} bytes", pcap_start.max_bytes);
                let mut service = self.service.write().await;
                service.pcap_start(pcap_start.into())
                    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
            }
            Command::PcapStop(_) => {
                log::info!("Received command: Stop PCAP recording");
                let mut service = self.service.write().await;
                service.pcap_stop()
                    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_matching_uid() {
        assert!(check_access(1000, 1000).is_ok());
    }

    #[test]
    fn denies_mismatched_uid() {
        assert!(check_access(1000, 1001).is_err());
    }
}
