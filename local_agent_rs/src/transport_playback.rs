// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use crate::{transport::Transport, Request, Response, Result};
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
    pub fn new(responses_path: &std::path::Path) -> Result<Self> {
        let file = std::fs::File::open(responses_path)?;

        // The responses list contains seconds to wait + the response
        // per entry.
        //
        // responses = [ (seconds, response), ... ]
        //
        let mut responses: Responses = serde_json::from_reader(file)?;
        responses.reverse();

        Ok(Self {
            responses: Mutex::new(responses),
        })
    }
}

#[async_trait]
impl Transport for TransportPlayback {
    /// Implements send method, but this implementation does nothing,
    /// it just drops the request.
    async fn send(&self, _request: Request) -> Result<()> {
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
            .pop()
            .expect("No more responses");

        // First we wait a bit before we return the response
        std::thread::sleep(std::time::Duration::from_secs(seconds));

        // Return the response
        Ok(response)
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}
