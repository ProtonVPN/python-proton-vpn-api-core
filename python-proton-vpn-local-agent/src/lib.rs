// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use pyo3::prelude::*;
// -----------------------------------------------------------------------------
mod agent_connection;
mod agent_connector;
mod agent_features;
mod error;
mod exception;
mod future;
mod reason;
mod state;
mod status;

const DEFAULT_TIMEOUT_IN_SECONDS: u64 = 10;

// -----------------------------------------------------------------------------
pub use agent_connection::AgentConnection;
pub use agent_connector::AgentConnector;
pub use agent_features::AgentFeatures;
pub use error::{Error, Result};
pub use exception::*;
pub use reason::{Reason, ReasonCode};
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

    Ok(())
}
