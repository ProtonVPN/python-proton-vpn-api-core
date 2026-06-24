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
use super::{Error, transport::Transport, Request, Response, Result};
use async_trait::async_trait;
use tokio::sync::Mutex;
// -----------------------------------------------------------------------------

/// The responses list contains seconds to wait + the response.
/// (seconds, Response)
type Responses = Vec<(u64, Response)>;

/// Implements a dummy transport layer for testing purposes.
/// The requests to the server are ignored and responses are hard coded.
pub struct TransportPlayback {
    responses: Mutex<Responses>,
}

impl TransportPlayback {
    pub fn new(responses_str: &str) -> Result<Self> {
        // The responses list contains seconds to wait + the response per entry.
        //
        // responses = [ (seconds, response), ... ]
        //
        let mut responses: Responses = serde_json::from_str(responses_str)?;
        responses.reverse();

        log::info!("TransportPlayback::new");

        Ok(Self {
            responses: Mutex::new(responses),
        })
    }
}

#[async_trait]
impl Transport for TransportPlayback {
    /// Implements send method, but this implementation does nothing,
    /// it just drops the request.
    async fn send(&self, request: Request) -> Result<()> {
        log::info!("TransportPlayback:send( {request:?} )");
        Ok(())
    }

    /// Implements recv method, this just returns the next response
    /// in the responses list, which is read from a json file.
    async fn recv(&self) -> Result<Response> {
        // Get the next response
        let (seconds, response) = self
            .responses
            .lock()
            .await
            .pop().ok_or(Error::NoMoreResponses)?;

        // First we wait a bit before we return the response
        std::thread::sleep(std::time::Duration::from_secs(seconds));

        log::info!("TransportPlayback:recv() -> {response:?}");

        // Return the response
        Ok(response)
    }

    async fn close(&self) -> Result<()> {
        log::info!("TransportPlayback:close()");
        Ok(())
    }
}
