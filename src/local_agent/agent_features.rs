// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
//
// This file is part of ProtonVPN.
//
// ProtonVPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ProtonVPN is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
// -----------------------------------------------------------------------------
use serde::{Deserialize, Serialize};
// -----------------------------------------------------------------------------

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[derive(Default)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "python", pyo3::pyclass)]
pub struct AgentFeatures {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub netshield_level: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub randomized_nat: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split_tcp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_forwarding: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarded_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jail: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bouncing: Option<String>,
}

#[cfg(feature = "python")]
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
    /// * `fowarded_port` - Port where traffic is being forwarded when port forwarding is enabled.
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
        forwarded_port=None,
        jail=None,
        bouncing=None,
    ))]
    pub fn new(
        netshield_level: Option<u8>,
        randomized_nat: Option<bool>,
        split_tcp: Option<bool>,
        port_forwarding: Option<bool>,
        forwarded_port: Option<u16>,
        jail: Option<bool>,
        bouncing: Option<String>,
    ) -> PyResult<Self> {
        Ok(Self {
            netshield_level,
            randomized_nat,
            split_tcp,
            port_forwarding,
            forwarded_port,
            jail,
            bouncing,
        })
    }

    #[getter]
    fn netshield_level(&self) -> PyResult<Option<u8>> {
        Ok(self.netshield_level)
    }

    #[getter]
    fn randomized_nat(&self) -> PyResult<Option<bool>> {
        Ok(self.randomized_nat)
    }

    #[getter]
    fn split_tcp(&self) -> PyResult<Option<bool>> {
        Ok(self.split_tcp)
    }

    #[getter]
    fn port_forwarding(&self) -> PyResult<Option<bool>> {
        Ok(self.port_forwarding)
    }

    #[getter]
    fn forwarded_port(&self) -> PyResult<Option<u16>> {
        Ok(self.forwarded_port)
    }

    #[getter]
    fn jail(&self) -> PyResult<Option<bool>> {
        Ok(self.jail)
    }

    #[getter]
    fn bouncing(&self) -> PyResult<Option<String>> {
        Ok(self.bouncing.clone())
    }
}
