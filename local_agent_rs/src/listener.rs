// use tokio::time::{sleep, timeout, Duration};
use crate::{
    request_tcp_port_forwarding, AgentConnection, AgentConnector, AgentFeatures, ConnectParams, Error, Result, StatusMessage
};

const DEFAULT_TIMEOUT_IN_SECONDS: u64 = 10;
const MAX_PORT_FORWARDING_RETRIES: u32 = 2;


#[derive(Clone)]
pub struct Listener {
    connection: AgentConnection
}

impl Listener {

    /// Establishes the agent connection and returns a Listener object wrapping it.
    ///
    /// # Arguments
    ///
    /// * `connection_params` - The parameters to establish the agent connection.
    pub async fn connect(connection_params: ConnectParams) -> Result<Self> {
        let connection = AgentConnector::connect(connection_params).await?;
        Ok(Self { connection })
    }

    /// Starts listening for local agent status updates.
    ///
    /// # Arguments
    ///
    /// * `callback` - Function that will be called with the local agent status/error as parameter.
    pub async fn listen <C> (
        &self,
        callback: C
    ) -> Result<()>
    where 
        C: Fn(Result<StatusMessage>) -> Result<()>
    {
        loop {
            let status = self.connection.read().await;
            match status {
                Ok(mut status) => {
                    if let Some(AgentFeatures {
                        port_forwarding: Some(true),
                        forwarded_port,
                        .. 
                    }) = &mut status.features {
                        *forwarded_port = Some(
                            request_tcp_port_forwarding(DEFAULT_TIMEOUT_IN_SECONDS, MAX_PORT_FORWARDING_RETRIES).await?
                        );
                    }
                    callback(Ok(status))?;
                },
                Err(Error::GetStatusError(error)) => callback(Err(Error::GetStatusError(error)))?,
                Err(error) => {
                    self.connection.close(DEFAULT_TIMEOUT_IN_SECONDS).await?;
                    return Err(error)
                },
            };
        }
    }

    /// Requests connection features.
    ///
    /// This method is expected to be called while listening to new agent statuses
    /// via the `listen()` method, and returns as soon as the request is done.
    /// The result is eventually sent via the `status_callback` passed to the
    /// `listen()` method.
    ///
    /// # Arguments
    ///
    /// * `features`: The requested features.
    /// * `timeout`: Amount of seconds before the request times out. 
    pub async fn request_features(
        &self,
        features: AgentFeatures,
        timeout_in_seconds: u64,
    ) -> Result<()> {
        self.connection.request_features(features, timeout_in_seconds).await?;
        Ok(())
    }
}
