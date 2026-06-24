// -----------------------------------------------------------------------------
// Copyright (c) 2025 Proton AG
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
//! Server status and load computation.
//!
//! Computes server loads based on user location and binary status data
//! for optimal server selection.

use crate::core::Result;
pub use proton_vpn_binary_status::{Country, Load, Location, Logical};

#[cfg(feature = "python")]
use pyo3::prelude::*;

// -----------------------------------------------------------------------------
// Used to compute the load of servers
// based on the user location, a list of servers and a binary status file.
#[cfg_attr(feature = "python", pyo3::pyclass)]
pub struct ServerStatus {
    status_id: String,
    logicals: Vec<Logical>,
    user_location: Option<Location>,
    user_country: Option<Country>,
}

impl ServerStatus {
    // Constructs a new ServerStatus instance.
    // `status_id` is a token that identifies the status endpoint, this is used
    // to obtain the status file from the server.
    // `logicals` is a list of servers to compute loads for, it contains
    // static information about the servers.
    // `user_location` is the location of the user, primarily the country and
    // the longitude/latitude.
    pub fn new(
        status_id: &str,
        logicals: Vec<Logical>,
        user_location: Option<Location>,
        user_country: Option<Country>,
    ) -> Self {
        Self {
            status_id: status_id.into(),
            logicals,
            user_location,
            user_country,
        }
    }

    // Updates the user location. This will be used next time
    // `compute_loads` is called.
    // This is useful if the user changes their location, for example,
    // if they move about whilst still logged in.
    pub fn set_user_location(
        &mut self,
        location: Option<Location>,
        country: Option<Country>,
    ) {
        self.user_location = location;
        self.user_country = country;
    }

    // Returns the token that identifies the status endpoint.
    pub fn status_id(&self) -> &str {
        &self.status_id
    }

    // Given a status file, computes the load for each server.
    pub fn compute_loads(&self, status_file: &[u8]) -> Result<Vec<Load>> {
        let mut loads = Vec::new();
        loads.resize(self.logicals.len(), Load::default());

        log::info!(
            "Computing loads for {} servers with user location: {:?}",
            self.logicals.len(),
            self.user_country
        );

        proton_vpn_binary_status::compute_loads(
            &mut loads,
            &self.logicals,
            status_file,
            &self.user_location,
            &self.user_country,
        )?;

        Ok(loads)
    }
}

#[cfg_attr(feature = "python", pyo3::pymethods)]
impl ServerStatus {
    #[cfg(feature = "python")]
    #[new]
    pub fn py_new(
        logicals: &Bound<PyAny>,
        user_location: &Bound<PyAny>,
        user_country: &Bound<PyAny>,
    ) -> Result<Self> {
        const STATUS_ID: &str = "StatusID";
        const LOGICAL_SERVERS: &str = "LogicalServers";

        let status: String = logicals.get_item(STATUS_ID)?.extract()?;
        Ok(Self::new(
            &status,
            pythonize::depythonize(&(logicals.get_item(LOGICAL_SERVERS)?))?,
            pythonize::depythonize(user_location)?,
            pythonize::depythonize(user_country)?,
        ))
    }

    #[cfg(feature = "python")]
    #[pyo3(name = "status_id")]
    pub fn py_status_id(&self) -> &str {
        self.status_id()
    }

    #[cfg(feature = "python")]
    #[pyo3(name = "compute_loads")]
    pub fn py_compute_loads<'py>(
        &self,
        py: Python<'py>,
        status_file: &[u8],
    ) -> Result<Bound<'py, PyAny>> {
        Ok(pythonize::pythonize(py, &self.compute_loads(status_file)?)?)
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;
    use proton_vpn_binary_status::{Location, StatusReference};

    fn make_server(status: u8, load: u8, partial_score: f32) -> [u8; 6] {
        [
            status,
            load,
            partial_score.to_le_bytes()[0],
            partial_score.to_le_bytes()[1],
            partial_score.to_le_bytes()[2],
            partial_score.to_le_bytes()[3],
        ]
    }

    fn make_status_file(servers: &[[u8; 6]]) -> Vec<u8> {
        let mut result = vec![1_u8, 0_u8, 0_u8, 0_u8];
        for server in servers {
            result.extend_from_slice(server);
        }
        result
    }

    fn make_servers_and_loads() -> (Vec<Logical>, Vec<u8>) {
        let servers = vec![
            Logical {
                status_reference: StatusReference {
                    index: 0,
                    penalty: 0.0,
                    cost: 0,
                },
                entry_location: Location {
                    latitude: 0.0,
                    longitude: 0.0,
                },
                exit_location: Location {
                    latitude: 0.0,
                    longitude: 0.0,
                },
                exit_country: Country::new(b"FR")
                    .expect("Invalid country code"),
            },
            Logical {
                status_reference: StatusReference {
                    index: 1,
                    penalty: 0.0,
                    cost: 0,
                },
                entry_location: Location {
                    latitude: 0.0,
                    longitude: 0.0,
                },
                exit_location: Location {
                    latitude: 0.0,
                    longitude: 0.0,
                },
                exit_country: Country::new(b"FR")
                    .expect("Invalid country code"),
            },
        ];

        let status_file = make_status_file(&[
            make_server(7, 50, 0.5_f32),
            make_server(7, 75, 0.25_f32),
            make_server(7, 90, 0.1_f32),
        ]);

        (servers, status_file)
    }

    #[test_log::test]
    fn test_server_status_compute_loads() {
        let (servers, status_file) = make_servers_and_loads();
        let servers_len = servers.len();

        let mut status = ServerStatus::new(
            "test_status_id",
            servers,
            Some(Location {
                latitude: 0.0,
                longitude: 0.0,
            }),
            Some(Country::new(b"FR").expect("Invalid country code")),
        );

        let loads = status
            .compute_loads(&status_file)
            .expect("Failed to compute loads");

        fn assert_score_eq(a: f64, b: f64) {
            const jitter: f64 = 0.01;
            if (a - b).abs() >= jitter {
                panic!("Scores are not equal: {} != {}", a, b);
            }
        }

        assert_eq!(loads.len(), 2);
        assert_eq!(servers_len, 2);

        // Compute scores based on the loads
        assert_score_eq(loads[0].score, 0.5);
        assert_score_eq(loads[1].score, 0.25);

        // Compute scores limited by distance
        status.set_user_location(
            Some(Location {
                latitude: 45.0,
                longitude: 0.0,
            }),
            Some(Country::new(b"FR").expect("Invalid country code")),
        );

        let loads = status
            .compute_loads(&status_file)
            .expect("Failed to compute loads");

        let distance = 5003.7725; // Distance in km
        let score = (10000.0 - (738000.0 / f64::max(distance, 1.0))) / 10000.0;

        assert_eq!(loads[0].is_enabled, true);
        assert_eq!(loads[0].is_visible, true);
        assert_eq!(loads[0].is_autoconnectable, true);
        assert_score_eq(loads[0].score, score);
        assert_eq!(loads[0].load, 50);

        assert_eq!(loads[1].is_enabled, true);
        assert_eq!(loads[1].is_visible, true);
        assert_eq!(loads[1].is_autoconnectable, true);
        assert_score_eq(loads[1].score, score);
        assert_eq!(loads[1].load, 75);
    }
}
