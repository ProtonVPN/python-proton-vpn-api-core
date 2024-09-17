// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use pyo3::prelude::*;
// -----------------------------------------------------------------------------
use local_agent_rs as la;

/// Contains all the features requested for a vpn connection
#[pyclass]
#[derive(Debug, Clone)]
pub struct AgentFeatures {
    features: la::AgentFeatures,
}

impl std::convert::From<AgentFeatures> for la::AgentFeatures {
    fn from(features: AgentFeatures) -> Self {
        features.features
    }
}

impl std::convert::From<la::AgentFeatures> for AgentFeatures {
    fn from(features: la::AgentFeatures) -> Self {
        Self { features }
    }
}

#[pymethods]
impl AgentFeatures {
    /// Creates a new AgentFeatures object, to be passed to
    /// AgentConnection::request_features.
    ///
    /// # Arguments
    ///
    /// * `netshield` - The netshield level.
    ///     The netshield level to use for this session.
    ///     0 - No netshield.
    ///     1 - Block malware
    ///     2 - Block malware, trackers and adverts
    /// * `randomized_nat` - Whether to enable randomized NAT.
    ///     Is random source port applied to outgoing NAT packets.
    /// * `split_tcp` - Whether to enable split TCP.
    ///     Is the performance enhanced proxy enabled for this session ?
    /// * `port_forwarding` - Whether to enable port forwarding.
    /// * `jail` - Whether to enable jailed mode.
    ///     Jail the user (vpn tunnel established, but not communicating to the rest of internet)
    /// * `bouncing` - The bouncing level.
    ///     The bouncing label selecting the outgoing source IP.
    ///
    #[new]
    #[pyo3(signature = (
        netshield_level=None,
        randomized_nat=None,
        split_tcp=None,
        port_forwarding=None,
        jail=None,
        bouncing=None,
    ))]
    pub fn new(
        netshield_level: Option<u8>,
        randomized_nat: Option<bool>,
        split_tcp: Option<bool>,
        port_forwarding: Option<bool>,
        jail: Option<bool>,
        bouncing: Option<String>,
    ) -> PyResult<Self> {
        Ok(Self {
            features: la::AgentFeatures {
                netshield_level,
                randomized_nat,
                split_tcp,
                port_forwarding,
                jail,
                bouncing,
            },
        })
    }

    #[getter]
    fn netshield_level(&self) -> PyResult<Option<u8>> {
        Ok(self.features.netshield_level)
    }

    #[getter]
    fn randomized_nat(&self) -> PyResult<Option<bool>> {
        Ok(self.features.randomized_nat)
    }

    #[getter]
    fn split_tcp(&self) -> PyResult<Option<bool>> {
        Ok(self.features.split_tcp)
    }

    #[getter]
    fn port_forwarding(&self) -> PyResult<Option<bool>> {
        Ok(self.features.port_forwarding)
    }

    #[getter]
    fn jail(&self) -> PyResult<Option<bool>> {
        Ok(self.features.jail)
    }

    #[getter]
    fn bouncing(&self) -> PyResult<Option<String>> {
        Ok(self.features.bouncing.clone())
    }
}
