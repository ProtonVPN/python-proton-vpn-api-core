// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
pub use proton_vpn_binary_status::{Load, Server, UserLocation};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    ProtonVpnBinaryStatus(#[from] proton_vpn_binary_status::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

// -----------------------------------------------------------------------------
// Used to compute the load of servers
// based on the user location, a list of servers and a binary status file.
pub struct ServerStatus {
    status_id: String,
    servers: Vec<Server>,
    user_location: UserLocation,
}

impl ServerStatus {
    // Constructs a new ServerStatus instance.
    // `status_id` is a token this identifies the status endpoint, this is used
    // to obtain the status file from the server.
    // `servers` is a list of servers to compute loads for, it contains
    // static information about the servers.
    // `user_location` is the location of the user, primarily the country and
    // the longitude/latitude.
    pub fn new(
        status_id: &str,
        servers: Vec<Server>,
        user_location: UserLocation,
    ) -> Self {
        Self {
            status_id: status_id.to_string(),
            servers,
            user_location,
        }
    }

    // Returns the token that identifies the status endpoint.
    pub fn status_id(&self) -> &str {
        &self.status_id
    }

    // Given a status file, computes the load for each server.
    pub fn compute_loads(&self, status_file: &[u8]) -> Result<Vec<Load>> {
        let mut loads = Vec::new();
        loads.resize(self.servers.len(), Load::default());

        proton_vpn_binary_status::compute_loads(
            &self.user_location,
            &mut loads,
            &self.servers,
            status_file,
        )?;

        Ok(loads)
    }

    // This is a utility primary for debugging purposes.
    // This provides a way to iterate over the servers and their loads,
    // and to print them as a json string.
    pub fn read_status(status_file: &[u8]) -> Result<proton_vpn_binary_status::Parser> {
        Ok(proton_vpn_binary_status::Parser::try_from(status_file)?)
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;
    use proton_vpn_binary_status::{Location, Status};

    const fn make_server(status: u8, load: u8, partial_score: f32) -> [u8; 6] {
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

    fn make_servers_and_loads() -> (Vec<Server>, Vec<u8>) {
        let servers = vec![
            Server {
                id: "server1".to_string(),
                status: Status {
                    index: 0,
                    penalty: 0.0,
                    cost: 0,
                },
                exit_location: Location {
                    lat: 0.0,
                    long: 0.0,
                },
                exit_country: "FR".to_string(),
                physical_servers: vec![],
            },
            Server {
                id: "server2".to_string(),
                status: Status {
                    index: 1,
                    penalty: 1.0,
                    cost: 1,
                },
                exit_location: Location {
                    lat: 0.0,
                    long: 0.0,
                },
                exit_country: "GB".to_string(),
                physical_servers: vec![],
            },
        ];

        let status_file = make_status_file(&[
            make_server(1, 57, 1.97),
            make_server(1, 75, 2.99),
            make_server(1, 56, 2.97),
        ]);

        (servers, status_file)
    }

    #[test]
    fn test_server_status_compute_loads() {
        let (servers, status_file) = make_servers_and_loads();
        let servers_len = servers.len();

        let status = ServerStatus::new(
            "test_status_id",
            servers,
            UserLocation {
                country: "FR".to_string(),
                location: Location {
                    lat: 0.0,
                    long: 0.0,
                },
            },
        );

        let loads = status
            .compute_loads(&status_file)
            .expect("Failed to compute loads");

        assert_eq!(loads.len(), servers_len);
    }

    #[test]
    fn test_server_status_read_status() {
        let (_, status_file) = make_servers_and_loads();

        let parsed_status = ServerStatus::read_status(&status_file)
            .expect("Failed to read status");

        assert_eq!(parsed_status.len(), 3);
        assert_eq!(parsed_status.index(0).unwrap().status, 1);
        assert_eq!(parsed_status.index(0).unwrap().load, 57);
        assert_eq!(parsed_status.index(0).unwrap().partial_score, 1.97);
        assert_eq!(parsed_status.index(1).unwrap().status, 1);
        assert_eq!(parsed_status.index(1).unwrap().load, 75);
        assert_eq!(parsed_status.index(1).unwrap().partial_score, 2.99);
        assert_eq!(parsed_status.index(2).unwrap().status, 1);
        assert_eq!(parsed_status.index(2).unwrap().load, 56);
        assert_eq!(parsed_status.index(2).unwrap().partial_score, 2.97);
    }
}
