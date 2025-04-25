// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
mod error;
// -----------------------------------------------------------------------------
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString};
// -----------------------------------------------------------------------------

pyo3::create_exception!(lib, ProtonVpnLibError, PyException);

const STATUS: &str = "Status";
const LOGICAL_SERVERS: &str = "LogicalServers";

fn init_logger() {
    env_logger::init();
}

#[pyclass]
struct ServerStatus(proton_vpn_lib_rs::ServerStatus);

#[pymethods]
impl ServerStatus {
    #[new]
    pub fn new<'py>(response: &Bound<'py, PyAny>) -> Result<Self, PyErr> {
        Ok(Self(proton_vpn_lib_rs::ServerStatus::new(
            response.get_item(STATUS)?.extract()?,
            pythonize::depythonize(&(response.get_item(LOGICAL_SERVERS)?))?,
        )))
    }

    pub fn status_id(&self) -> &str {
        self.0.status_id()
    }
}

#[pymodule]
/// This is the entry point for the python module.
fn lib(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ServerStatus>()?;
    m.add("ProtonVpnLibError", m.py().get_type::<ProtonVpnLibError>())?;

    // Start the logger when the module is returned.
    init_logger();

    Ok(())
}
