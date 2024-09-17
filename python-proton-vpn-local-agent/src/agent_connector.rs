// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use pyo3::prelude::*;
// -----------------------------------------------------------------------------
use local_agent_rs as la;
// -----------------------------------------------------------------------------
use crate::{future::future, AgentConnection, DEFAULT_TIMEOUT_IN_SECONDS};

#[pyclass]
/// Creator of AgentConnections.
/// see AgentConnector::connect
pub struct AgentConnector {}

#[pymethods]
impl AgentConnector {
    /// Creates a new AgentConnector.
    #[new]
    pub fn new() -> PyResult<Self> {
        Ok(Self {})
    }

    /// Connects to the LocalAgent server.
    ///
    /// This is an async function, and will return a future that will resolve
    /// to an AgentConnection.
    ///
    /// # Arguments
    ///
    /// * `domain` - The name of the local agent server to connect to as a string.
    /// * `key` - The private key pks8 formatted in pem encoding as a string.
    /// * `cert` - The certificate in pem encoding as a string.
    ///
    #[pyo3(signature = (domain, key, cert, timeout_in_seconds=DEFAULT_TIMEOUT_IN_SECONDS))]
    pub fn connect<'p>(
        &self,
        py: Python<'p>,
        domain: String,
        key: String,
        cert: String,
        timeout_in_seconds: u64,
    ) -> PyResult<Bound<'p, PyAny>> {
        future(py, async move {
            Ok(AgentConnection::new(
                la::AgentConnector::connect(
                    &domain,
                    &key,
                    &cert,
                    timeout_in_seconds,
                )
                .await?,
            ))
        })
    }

    /// Reads a string of json containing responses and returns an
    /// AgentConnection object, which behaves like a real connection.
    ///
    /// This is an async function, and will return a future that will resolve
    /// to an AgentConnection.
    ///
    /// # Arguments
    ///
    /// * `responses` - A string of json containing reponses.
    ///
    #[pyo3(signature = (responses))]
    pub fn playback<'p>(
        &self,
        py: Python<'p>,
        responses: String,
    ) -> PyResult<Bound<'p, PyAny>> {
        future(py, async move {
            Ok(AgentConnection::new(
                la::AgentConnector::playback(&responses).await?,
            ))
        })
    }
}
