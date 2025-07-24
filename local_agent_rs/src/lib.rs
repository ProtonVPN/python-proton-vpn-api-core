// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

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
pub use error::{Error, Result};
pub use listener::Listener;
pub use message::*;
pub use port_forwarding::request_tcp_port_forwarding;
pub use reason_code::*;
pub use transport_playback::TransportPlayback;
pub use transport_stream::TransportStream;
