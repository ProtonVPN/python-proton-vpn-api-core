// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
mod error;
// -----------------------------------------------------------------------------
use pyo3::prelude::*;
// -----------------------------------------------------------------------------
use error::Result;

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
    pub fn new(
        logicals: &Bound<PyAny>,
        user_location: &Bound<PyAny>,
        user_country: &Bound<PyAny>,
    ) -> Result<Self> {
        let status: String = logicals.get_item(STATUS)?.extract()?;
        Ok(Self(proton_vpn_lib_rs::ServerStatus::new(
            &status,
            pythonize::depythonize(&(logicals.get_item(LOGICAL_SERVERS)?))?,
            pythonize::depythonize(user_location)?,
            pythonize::depythonize(user_country)?,
        )))
    }

    pub fn status_id(&self) -> &str {
        self.0.status_id()
    }

    pub fn compute_loads<'py>(
        &self,
        py: Python<'py>,
        status_file: &[u8],
    ) -> Result<Bound<'py, PyAny>> {
        Ok(pythonize::pythonize(
            py,
            &self.0.compute_loads(status_file)?,
        )?)
    }
}

#[pymodule]
/// This is the entry point for the python module.
fn lib(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ServerStatus>()?;
    m.add(
        "ProtonVpnLibError",
        m.py().get_type::<error::ProtonVpnLibError>(),
    )?;

    // Start the logger when the module is returned.
    init_logger();

    Ok(())
}
