// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
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

const DEFAULT_TIMEOUT_IN_SECONDS: u64 = 10;

mod agent_connection;
mod agent_connector;
mod agent_features;
mod error;
mod listener;
mod message;
mod port_forwarding;
mod reason_code;
mod transport;
mod transport_playback;
mod transport_stream;

// -----------------------------------------------------------------------------
pub use agent_connection::AgentConnection;
pub use agent_connector::{AgentConnector, ConnectParams};
pub use agent_features::AgentFeatures;
pub use transport_stream::TransportStream;
pub use transport_playback::TransportPlayback;
pub use error::{Error, Result};
pub use listener::Listener;
pub use message::*;
pub use port_forwarding::request_tcp_port_forwarding;
pub use reason_code::*;

#[cfg(feature = "python")]
pub mod python;