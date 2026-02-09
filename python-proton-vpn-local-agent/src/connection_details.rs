pub use local_agent_rs as la;
use pyo3::prelude::{pyclass, pymethods, PyResult};
use std::fmt;

#[pyclass(get_all)]
#[derive(Clone)]
pub struct ConnectionDetails {
    pub device_ip: Option<String>,
    pub device_country: Option<String>,
    pub server_ipv4: Option<String>,
    pub server_ipv6: Option<String>,
}

impl fmt::Debug for ConnectionDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let truncated_device_ip = if let Some(ip) = &self.device_ip {
            let last_dot_index: usize =
                ip.rfind('.').expect("IP address contains no dots.") + 1;
            let sliced_string = &ip[0..ip.len() - (ip.len() - last_dot_index)];
            let mut truncated_string = String::from(sliced_string);
            truncated_string.push_str("xxx");
            truncated_string
        } else {
            "None".to_string()
        };
        write!(
            f,
            "ConnectionDetails {{ device_ip: {:?}, device_country: {:?}, server_ipv4: {:?}, server_ipv6: {:?} }}",
            truncated_device_ip, self.device_country, self.server_ipv4, self.server_ipv6
        )
    }
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
