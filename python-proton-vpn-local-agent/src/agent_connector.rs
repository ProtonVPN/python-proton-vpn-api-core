// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use pyo3::prelude::*;
// -----------------------------------------------------------------------------
use local_agent_rs as la;
// -----------------------------------------------------------------------------
use crate::result_to_py;
use crate::{AgentConnection, DEFAULT_TIMEOUT_IN_SECONDS};

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
        pyo3_asyncio_0_21::tokio::future_into_py(py, async move {
            let connection = la::AgentConnector::connect(
                &domain,
                &key,
                &cert,
                timeout_in_seconds,
            )
            .await;

            let new_agent_connection =
                AgentConnection::new(result_to_py(connection)?);

            result_to_py(Ok(new_agent_connection))
        })
    }

    /// Opens a LocalAgent playback file and returns an AgentConnection object,
    /// which behaves like a real connection, but reads responses from the file.
    ///
    /// This is an async function, and will return a future that will resolve
    /// to an AgentConnection.
    ///
    /// # Arguments
    ///
    /// * `playback_file` - The path to the playback file.
    ///
    #[pyo3(signature = (playback_file))]
    pub fn playback<'p>(
        &self,
        py: Python<'p>,
        playback_file: std::path::PathBuf,
    ) -> PyResult<Bound<'p, PyAny>> {
        pyo3_asyncio_0_21::tokio::future_into_py(py, async move {
            let connection = la::AgentConnector::playback(&playback_file).await;

            let new_agent_connection =
                AgentConnection::new(result_to_py(connection)?);

            result_to_py(Ok(new_agent_connection))
        })
    }
}
