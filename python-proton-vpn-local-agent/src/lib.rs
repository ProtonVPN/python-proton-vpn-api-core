// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use pyo3::prelude::*;
// -----------------------------------------------------------------------------
mod agent_connection;
mod agent_connector;
mod agent_features;
mod connection_details;
mod error;
mod exception;
mod future;
mod listener;
mod logger;
mod reason;
mod state;
mod status;

const DEFAULT_TIMEOUT_IN_SECONDS: u64 = 10;

// -----------------------------------------------------------------------------
pub use agent_connection::AgentConnection;
pub use agent_connector::AgentConnector;
pub use agent_features::AgentFeatures;
pub use connection_details::ConnectionDetails;
pub use error::{Error, Result};
pub use exception::*;
pub use listener::Listener;
pub use reason::{Reason, ReasonCode};
pub use state::State;
pub use status::Status;

/// Initialize the logger for the local agent, this forwards to the
/// python logger.
#[pyfunction]
fn init_logger(get_logger: PyObject) -> PyResult<PyObject> {
    Python::with_gil(|py| -> PyResult<PyObject> {
        // Create a new rust logger instance, this will forward log messages to
        // the python logger.
        let logger = logger::Logger::new(py, get_logger)?;

        // Get a reference to the python logger so it can be configured at
        // the python level.
        let py_logger = logger.get_py_logger().clone_ref(py);

        // We have our own logger implementation which delegates to the python
        // logger. The log module takes a heap allocated object that implements
        // the log::Log trait.
        //
        // The only alternative is to use log::set_logger which requires a
        // `static &log::Log trait object. Making our wrapping logger static is
        // possible but complicates it as it means it has to support being
        // instantiated without the python logger, as that is how it would be
        // initialized.
        log::set_boxed_logger(Box::new(logger))
            .map_err(Error::SetLoggerError)?;

        // Set the rust log level to something sensible but not too verbose,
        // let the python logger filter.
        log::set_max_level(logger::DEFAULT_LOG_LEVEL.to_level_filter());

        Ok(py_logger)
    })
}

#[pymodule]
/// This is the entry point for the python module.
pub fn local_agent(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Register the exceptions
    exception::register(m)?;

    // Add the AgentConnection and AgentConnector classes to the module.
    m.add_class::<AgentConnector>()?;
    m.add_class::<AgentConnection>()?;
    m.add_class::<AgentFeatures>()?;
    m.add_class::<State>()?;
    m.add_class::<ReasonCode>()?;
    m.add_class::<Reason>()?;
    m.add_class::<Status>()?;
    m.add_class::<ConnectionDetails>()?;
    m.add_class::<Listener>()?;

    m.add_function(wrap_pyfunction!(init_logger, m)?)?;

    Ok(())
}
