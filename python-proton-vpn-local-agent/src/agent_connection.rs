// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use local_agent_rs as la;
use pyo3::prelude::*;
// -----------------------------------------------------------------------------
use crate::{result_to_py, AgentFeatures, Status};
// -----------------------------------------------------------------------------

pub const DEFAULT_TIMEOUT_IN_SECONDS: u64 = 10;

/// Represents an active connection to the LocalAgent server.
///
/// One of these is needed per connection to a LocalAgent server.
#[pyclass]
pub struct AgentConnection {
    agent_connection: la::AgentConnection,
}

impl AgentConnection {
    /// Creates a new AgentConnection, dont use this directly, use
    /// AgentConnector::connect instead.
    pub(crate) fn new(agent_connection: la::AgentConnection) -> Self {
        Self { agent_connection }
    }
}

#[pymethods]
impl AgentConnection {
    #[pyo3(signature = (timeout_in_seconds=DEFAULT_TIMEOUT_IN_SECONDS))]
    pub fn request_status<'p>(
        &self,
        py: Python<'p>,
        timeout_in_seconds: u64,
    ) -> PyResult<Bound<'p, PyAny>> {
        let agent_connection = self.agent_connection.clone();
        pyo3_asyncio_0_21::tokio::future_into_py(py, async move {
            result_to_py(
                agent_connection.request_status(timeout_in_seconds).await,
            )?;
            Ok(())
        })
    }

    #[pyo3(signature = (features, timeout_in_seconds=DEFAULT_TIMEOUT_IN_SECONDS))]
    pub fn request_features<'p>(
        &self,
        py: Python<'p>,
        features: AgentFeatures,
        timeout_in_seconds: u64,
    ) -> PyResult<Bound<'p, PyAny>> {
        let agent_connection = self.agent_connection.clone();
        pyo3_asyncio_0_21::tokio::future_into_py(py, async move {
            result_to_py(
                agent_connection
                    .request_features(features.into(), timeout_in_seconds)
                    .await,
            )?;
            Ok(())
        })
    }

    /// Closes the local agent connection.
    #[pyo3(signature = (timeout_in_seconds=DEFAULT_TIMEOUT_IN_SECONDS))]
    pub fn close<'p>(
        &self,
        py: Python<'p>,
        timeout_in_seconds: u64,
    ) -> PyResult<Bound<'p, PyAny>> {
        let agent_connection = self.agent_connection.clone();
        pyo3_asyncio_0_21::tokio::future_into_py(py, async move {
            result_to_py(agent_connection.close(timeout_in_seconds).await)?;
            Ok(())
        })
    }

    /// Reads the local agent response.
    #[pyo3()]
    pub fn read<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        let agent_connection = self.agent_connection.clone();
        pyo3_asyncio_0_21::tokio::future_into_py(py, async move {
            let status_response = result_to_py(agent_connection.read().await)?;
            result_to_py(Ok(Status::from(status_response)))
        })
    }
}
