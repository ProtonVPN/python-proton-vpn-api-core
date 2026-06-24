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
#[cfg(feature = "local_agent")]
mod server;

#[cfg(feature = "local_agent")]
use tokio::net::TcpStream;

#[cfg(feature = "local_agent")]
#[tokio::test]
async fn test_request_status() {
    use proton_vpn_linux::local_agent::AgentConnection;
    use proton_vpn_linux::local_agent::State;
    use proton_vpn_linux::local_agent::TransportStream;
    use server::Server;

    // The server address
    let server_addr = String::from("127.0.0.1:8080");

    // Create a new server
    let _server = Server::new(&server_addr)
        .await
        .expect("Server couldn't be created");

    // Create a new TCP stream
    let tcp_stream = TcpStream::connect(server_addr)
        .await
        .expect("TCP stream couldn't be open");

    let (read, write) = tokio::io::split(tcp_stream);

    // Create a new AgentConnection
    // and send a request to get the status
    let connection = AgentConnection::new(TransportStream::new(read, write))
        .expect("AgentConnection couldn't be created");

    connection
        .request_status(1, None)
        .await
        .expect("get-status failed");

    let response = connection.read().await.expect("read failed");

    assert!(std::matches!(response.state, State::Connected));
}
