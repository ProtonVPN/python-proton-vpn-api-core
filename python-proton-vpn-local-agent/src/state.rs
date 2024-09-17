// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
pub use local_agent_rs as la;
use pyo3::prelude::*;

#[pyclass]
#[derive(Clone, Debug)]
#[allow(non_camel_case_types)]
pub enum State {
    CONNECTED,
    HARD_JAILED,
    DISCONNECTED,
}

#[pymethods]
impl State {
    // This method is used to convert the object to a string for easier
    /// debugging in Python.
    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{:?}", self))
    }
}

impl std::convert::From<la::State> for State {
    fn from(state: la::State) -> Self {
        match state {
            la::State::Connected => State::CONNECTED,
            la::State::HardJailed => State::HARD_JAILED,
            la::State::Disconnected => State::DISCONNECTED,
        }
    }
}
