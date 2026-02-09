use crate::{
    request_tcp_port_forwarding, AgentConnection, AgentConnector,
    AgentFeatures, ConnectParams, Error, Result, StatusMessage
};

const DEFAULT_TIMEOUT_IN_SECONDS: u64 = 10;
const PORT_FORWARDING_REFRESH_INTERVAL: u64 = 60;
const MAX_PORT_FORWARDING_RETRIES: u32 = 2;

fn swallow_errors<T>(result : Result<T>, error_message: &str) -> Option<T> {
    match result {
        Ok(result) => Some(result),
        Err(error) => {
            log::error!("{error_message}: {error}");
            None
        }
    }
}

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

    /// Starts playback of recorded agent responses.
    pub async fn playback(responses: &str) -> Result<Self> {
        let connection = AgentConnector::playback(responses).await?;
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
        let mut old_status: Option<StatusMessage> = None;

        loop {
            let new_status_future = tokio::time::timeout(
                std::time::Duration::from_secs(PORT_FORWARDING_REFRESH_INTERVAL),
                self.connection.read()
            ).await;
            
            match new_status_future {
                Ok(new_status) => {
                    match new_status {
                        Ok(mut new_status) => {
                            _ = swallow_errors(
                                self.request_port_forwarding_lease(&mut new_status).await,
                                "Port forwarding refresh failed."
                            );
                            old_status = Some(new_status.clone());
                            callback(Ok(new_status))?;
                        },
                        Err(Error::GetStatusError(error)) => callback(Err(Error::GetStatusError(error)))?,
                        Err(error) => {
                            self.connection.close(DEFAULT_TIMEOUT_IN_SECONDS).await?;
                            return Err(error)
                        },
                    };
                },
                Err(_port_forwarding_refreh) => {
                    // The port forwarding lease needs to be refreshed every minute. If no new status message is
                    // received the socket read will time out and the port lease will be refreshed if required.
                    if let Some(status) = &mut old_status {
                        let port_changed = swallow_errors(
                            self.request_port_forwarding_lease(status).await,
                            "Port forwarding request failed."
                        );
                        if let Some(true) = port_changed {
                            callback(Ok(status.clone()))?;
                        }
                    }
                }
            };
        }
    }

    async fn request_port_forwarding_lease(&self, status: &mut StatusMessage) -> Result<bool> {
        if let Some(AgentFeatures {
            port_forwarding: Some(true),
            forwarded_port,
            .. 
        }) = &mut status.features {
            let port = request_tcp_port_forwarding(DEFAULT_TIMEOUT_IN_SECONDS, MAX_PORT_FORWARDING_RETRIES).await?;
            let some_port = Some(port);
            if *forwarded_port != some_port {
                *forwarded_port = some_port;
                log::info!("Forwarded port updated.");
                return Ok(true);
            };
        }
        Ok(false)
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
