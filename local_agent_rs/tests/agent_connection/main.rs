// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
mod server;

use local_agent_rs::AgentConnection;
use local_agent_rs::State;
use local_agent_rs::TransportStream;
use server::Server;
use tokio::net::TcpStream;

#[tokio::test]
async fn test_request_status() {
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
    let mut connection =
        AgentConnection::new(TransportStream::new(read, write))
            .expect("AgentConnection couldn't be created");

    connection
        .request_status(1)
        .await
        .expect("get-status failed");

    let response = connection.read().await.expect("read failed");

    assert!(std::matches!(response.state, State::Connected));
}
