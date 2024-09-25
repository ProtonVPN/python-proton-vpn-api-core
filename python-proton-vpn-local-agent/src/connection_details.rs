pub use local_agent_rs as la;
use pyo3::prelude::{pyclass, pymethods, PyResult};

#[pyclass(get_all)]
#[derive(Clone, Debug)]
pub struct ConnectionDetails {
    pub device_ip: Option<String>,
    pub device_country: Option<String>,
    pub server_ipv4: Option<String>,
    pub server_ipv6: Option<String>,
}

#[pymethods]
impl ConnectionDetails {
    /// This method is used to convert the object to a string for easier
    /// debugging in Python.
    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{:?}", self))
    }
}

impl From<la::ConnectionDetails> for ConnectionDetails {
    fn from(connection_details: la::ConnectionDetails) -> Self {
        ConnectionDetails {
            device_ip: connection_details.device_ip,
            device_country: connection_details.device_country,
            server_ipv4: connection_details.server_ipv4,
            server_ipv6: connection_details.server_ipv6,
        }
    }
}
