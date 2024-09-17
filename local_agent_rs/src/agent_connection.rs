// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use crate::{
    transport::Transport, AgentFeatures, Error, Request, Response, Result,
    StatusGet, StatusMessage,
};
use std::sync::Arc;
// -----------------------------------------------------------------------------

/// Represents an active connection to the LocalAgent server.
///
/// One of these is needed per connection to a LocalAgent server.
#[derive(Clone)]
pub struct AgentConnection {
    transport: Arc<dyn Transport>,
}

impl AgentConnection {
    /// Creates a new AgentConnection, dont use this directly, use
    /// AgentConnector::connect instead.
    pub fn new<T>(transport: T) -> Result<Self>
    where
        T: Transport + 'static,
    {
        Ok(Self {
            transport: Arc::new(transport),
        })
    }

    /// Requests the local agent status. This method does not return anything.
    /// Eventually the local agent server will push the status, which can then
    /// be read via the read() method.
    pub async fn request_status(&self, timeout_in_seconds: u64) -> Result<()> {
        tokio::time::timeout(
            std::time::Duration::from_secs(timeout_in_seconds),
            async move {
                self.transport
                    .send(Request {
                        status_get: Some(StatusGet {}),
                        features_set: None,
                    })
                    .await
            },
        )
        .await?
    }

    /// Requests the local agent status. This method does not return anything.
    /// Eventually the local agent server will push the status, which can then
    /// be read via the read() method.
    pub async fn request_features(
        &self,
        features: AgentFeatures,
        timeout_in_seconds: u64,
    ) -> Result<()> {
        tokio::time::timeout(
            std::time::Duration::from_secs(timeout_in_seconds),
            async move {
                self.transport
                    .send(Request {
                        status_get: None,
                        features_set: Some(features),
                    })
                    .await
            },
        )
        .await?
    }

    /// Closes the connection.
    pub async fn close(&self, timeout_in_seconds: u64) -> Result<()> {
        tokio::time::timeout(
            std::time::Duration::from_secs(timeout_in_seconds),
            self.transport.close(),
        )
        .await?
    }

    /// Asynchronously awaits until the local agent server pushes a response and
    /// returns it.
    pub async fn read(&self) -> Result<StatusMessage> {
        // Receive the response from the server.
        let response = self.transport.recv().await?;

        // Interpret the response from the server
        match response {
            // If the response contains a status message, return it.
            Response {
                status: Some(status),
                error: None,
            } => Ok(status),

            // If the response contains an error, return it.
            Response {
                status: _,
                error: Some(e),
            } => Err(Error::GetStatusError(e)),

            // If the response contains neither a status nor an error, return
            // an error.
            _ => Err(Error::NoStatusReturned),
        }
    }
}
