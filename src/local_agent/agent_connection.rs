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
use super::{
    transport::Transport, AgentFeatures, Error, Request, Response, Result,
    StatusGet, Status
};
use std::sync::Arc;
// -----------------------------------------------------------------------------

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
use super::{DEFAULT_TIMEOUT_IN_SECONDS, super::python::{await_py, future}};

/// Represents an active connection to the LocalAgent server.
///
/// One of these is needed per connection to a LocalAgent server.
#[cfg_attr(feature = "python", pyo3::pyclass)]
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
    pub async fn request_status(&self, timeout_in_seconds: u64, features_statistics: Option<bool>) -> Result<()> {
        tokio::time::timeout(
            std::time::Duration::from_secs(timeout_in_seconds),
            async move {
                self.transport
                    .send(Request {
                        status_get: Some(StatusGet { features_statistics }),
                        features_set: None,
                    })
                    .await
            },
        )
        .await?
    }

    /// Sends a features request to the local agent. This method does not return anything.
    /// Eventually the local agent server will push a status response, which can then
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
    pub async fn read(&self) -> Result<Status> {
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

#[cfg(feature = "python")]
#[pyo3::pymethods]
impl AgentConnection {
    /// Requests the status of the local agent.
    ///
    /// This returns right away, and the result can be read later using the
    /// read method.
    #[pyo3(name="request_status", signature = (timeout_in_seconds=DEFAULT_TIMEOUT_IN_SECONDS))]
    pub fn py_request_status<'p>(
        &self,
        py: Python<'p>,
        timeout_in_seconds: u64,
    ) -> PyResult<Bound<'p, PyAny>> {
        await_py!(py, self.request_status(timeout_in_seconds, None))
    }

    /// Makes a new feature request from the local agent.
    ///
    /// This returns right away, and the result can be read later using the
    /// read method.
    #[pyo3(name="request_features", signature = (features, timeout_in_seconds=DEFAULT_TIMEOUT_IN_SECONDS))]
    pub fn py_request_features<'p>(
        &self,
        py: Python<'p>,
        features: AgentFeatures,
        timeout_in_seconds: u64,
    ) -> PyResult<Bound<'p, PyAny>> {
        await_py!(py, self.request_features(features, timeout_in_seconds))
    }

    /// Closes the local agent connection.
    #[pyo3(name="close", signature = (timeout_in_seconds=DEFAULT_TIMEOUT_IN_SECONDS))]
    pub fn py_close<'p>(
        &self,
        py: Python<'p>,
        timeout_in_seconds: u64,
    ) -> PyResult<Bound<'p, PyAny>> {
        await_py!(py, self.close(timeout_in_seconds))
    }

    /// Reads the local agent response.
    #[pyo3(name="read")]
    pub fn py_read<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        await_py!(py, self.read())
    }
}