// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
pub use local_agent_rs as la;
use pyo3::prelude::*;

#[pyclass(eq, eq_int)]
#[derive(Clone, Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum State {
    CONNECTED,
    HARD_JAILED,
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
        }
    }
}
