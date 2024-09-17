// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use pyo3::prelude::*;
// -----------------------------------------------------------------------------
mod agent_connection;
mod agent_connector;
mod agent_features;
mod error;
mod reason;
mod result_to_py;
mod state;
mod status;
// -----------------------------------------------------------------------------
pub use agent_connection::{AgentConnection, DEFAULT_TIMEOUT_IN_SECONDS};
pub use agent_connector::AgentConnector;
pub use agent_features::AgentFeatures;
pub use error::{ErrorMessage, ExpiredCertificateError, LocalAgentError};
pub use reason::{Reason, ReasonCode};
pub use result_to_py::result_to_py;
pub use state::State;
pub use status::Status;

#[pyfunction]
fn init() {
    env_logger::init();
}

#[pymodule]
/// This is the entry point for the python module.
fn local_agent(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(init, m)?)?;

    m.add(
        "LocalAgentError",
        m.py().get_type_bound::<LocalAgentError>(),
    )?;
    m.add(
        "ExpiredCertificateError",
        m.py().get_type_bound::<ExpiredCertificateError>(),
    )?;
    m.add("ErrorMessage", m.py().get_type_bound::<ErrorMessage>())?;

    // Add the AgentConnection and AgentConnector classes to the module.
    m.add_class::<AgentConnector>()?;
    m.add_class::<AgentConnection>()?;
    m.add_class::<AgentFeatures>()?;
    m.add_class::<State>()?;
    m.add_class::<ReasonCode>()?;
    m.add_class::<Reason>()?;
    m.add_class::<Status>()?;
    Ok(())
}
