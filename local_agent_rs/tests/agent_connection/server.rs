// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use local_agent_rs::{Request, Response, Result, State, StatusMessage};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;

pub struct Server {
    _server_task: tokio::task::JoinHandle<Result<()>>,
}

impl Server {
    /// Create a new Server instance.
    /// # Arguments
    /// * `address` - The address to bind the server to.
    /// # Returns
    /// A new Server instance.
    /// # Errors
    /// Returns an error if the server couldn't be created.
    pub async fn new(address: &str) -> Result<Server> {
        let server_addr = address.to_owned();
        let (tx, mut rx) = mpsc::channel::<u8>(100);
        let task =
            tokio::spawn(async move { Server::run(server_addr, tx).await });

        rx.recv().await;

        Ok(Server { _server_task: task })
    }

    async fn run(addr: String, sender: Sender<u8>) -> Result<()> {
        let listener = TcpListener::bind(&addr).await?;
        let _ = sender.send(0).await;
        log::info!("Listening on: {}", addr);
        let (mut socket, _) = listener.accept().await?;

        // In a loop, read data from the socket and write the data back.
        log::info!("Waiting for data...");
        let request_length: usize = socket.read_u32().await?.try_into()?;
        let mut buf = vec![0u8; request_length];
        socket.read_exact(&mut buf).await?;
        let request_str = std::str::from_utf8(&buf)?;
        log::info!("received: {}", request_str);
        let _request = serde_json::from_str::<Request>(request_str)
            .expect("unable to deserialize Request");

        let response = Response {
            status: Some(StatusMessage {
                state: State::Connected,
                reason: None,
                features: None,
                connection_details: None,
            }),
            error: None,
        };

        let response_str = serde_json::to_string(&response)
            .expect("unable to serialize Response");

        log::info!("sending: {}", &response_str);
        let payload = response_str.into_bytes();
        let payload_length: [u8; 4] = (payload.len() as u32).to_be_bytes();
        socket.write_all(&payload_length).await?;
        socket.write_all(&payload).await?;

        Ok(())
    }
}
