use crate::{
    error::Error, future::future, AgentFeatures, Status,
    DEFAULT_TIMEOUT_IN_SECONDS,
};
use local_agent_rs as la;
use pyo3::prelude::*;
use pyo3::types::PyType;

#[pyclass]
pub struct Listener {
    listener: la::Listener,
}

#[pymethods]
impl Listener {
    /// Starts the local agent listener.
    ///
    /// This is an async function, and will return a future that will resolve
    /// to a Listener.
    ///
    /// # Arguments
    ///
    /// * `domain` - The name of the local agent server to connect to as a string.
    /// * `key` - The private key pks8 formatted in pem encoding as a string.
    /// * `cert` - The certificate in pem encoding as a string.
    /// * `timeout_in_seconds` - Optional timeout used to stablish the connection.
    ///
    #[classmethod]
    #[pyo3(signature = (domain, key, cert, timeout_in_seconds=DEFAULT_TIMEOUT_IN_SECONDS))]
    pub fn connect<'p>(
        _cls: &Bound<'_, PyType>,
        py: Python<'p>,
        domain: String,
        key: String,
        cert: String,
        timeout_in_seconds: u64,
    ) -> PyResult<Bound<'p, PyAny>> {
        future(py, async move {
            let connection_params = la::ConnectParams {
                domain,
                key,
                cert,
                timeout_in_seconds,
            };
            Ok(Listener {
                listener: la::Listener::connect(connection_params).await?,
            })
        })
    }

    #[classmethod]
    #[pyo3(signature = (responses))]
    pub fn playback<'p>(
        _cls: &Bound<'_, PyType>,
        py: Python<'p>,
        responses: String,
    ) -> PyResult<Bound<'p, PyAny>> {
        future(py, async move {
            Ok(Listener {
                listener: la::Listener::playback(&responses).await?,
            })
        })
    }

    /// Starts listening for local agent status updates.
    ///
    /// # Arguments
    ///
    /// * `status_callback` - Function that will be called with the new local agent status as parameter.
    /// * `error_callback` - Function that will be called with the local agent error as parameter, when they occur.
    pub fn listen<'p>(
        &self,
        py: Python<'p>,
        status_callback: PyObject,
        error_callback: PyObject,
    ) -> PyResult<Bound<'p, PyAny>> {
        let listener = self.listener.clone();
        let callback = move |result: la::Result<la::StatusMessage>| {
            let py_result: PyResult<Status> = result
                .map(Status::from)
                .map_err(|error| Error::LocalAgent(error).into());

            Python::with_gil(|py| {
                let cb_result = match py_result {
                    Ok(response) => status_callback.call1(py, (response,)),
                    Err(error) => error_callback.call1(py, (error,)),
                };
                if let Err(error) = cb_result {
                    log::error!(
                        "Error calling callback: {:?}",
                        error.value(py).to_string()
                    );
                }
            });

            Ok(())
        };

        future(py, async move {
            listener.listen(callback).await?;
            Ok(())
        })
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
    #[pyo3(signature = (features, timeout_in_seconds=DEFAULT_TIMEOUT_IN_SECONDS))]
    pub fn request_features<'p>(
        &self,
        py: Python<'p>,
        features: AgentFeatures,
        timeout_in_seconds: u64,
    ) -> PyResult<Bound<'p, PyAny>> {
        let listener = self.listener.clone();
        future(py, async move {
            listener
                .request_features(features.into(), timeout_in_seconds)
                .await?;
            Ok(())
        })
    }
}
