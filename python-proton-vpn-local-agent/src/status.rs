// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use crate::{reason::Reason, state::State, AgentFeatures};
pub use local_agent_rs as la;
use pyo3::prelude::*;

#[pyclass]
#[derive(Clone, Debug)]
pub struct Status {
    #[pyo3(get)]
    state: State,
    #[pyo3(get)]
    reason: Option<Reason>,
    #[pyo3(get)]
    features: Option<AgentFeatures>,
}

#[pymethods]
impl Status {
    /// This method is used to convert the Status object to a string for easier
    /// debugging in Python.
    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{:?}", self))
    }
}

impl std::convert::From<la::StatusMessage> for Status {
    fn from(status: la::StatusMessage) -> Self {
        Status {
            state: State::from(status.state),
            reason: status.reason.map(Reason::from),
            features: status.features.map(AgentFeatures::from),
        }
    }
}
