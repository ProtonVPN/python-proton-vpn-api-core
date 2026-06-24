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
use super::{transport::Transport, Error, Request, Response, Result};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
// -----------------------------------------------------------------------------

/// Implements a transport layer using a tokio AsyncReadExt and AsyncWriteExt
/// trait, this can be a TLS stream or a TCP stream or anything that implements
/// these traits.
pub struct TransportStream<Read, Write>
where
    Read: AsyncReadExt + std::marker::Unpin + Send,
    Write: AsyncWriteExt + std::marker::Unpin + Send,
{
    read: Mutex<Option<Read>>,
    write: Mutex<Option<Write>>,
}

impl<Read, Write> TransportStream<Read, Write>
where
    Read: AsyncReadExt + std::marker::Unpin + Send,
    Write: AsyncWriteExt + std::marker::Unpin + Send,
{
    pub fn new(read: Read, write: Write) -> Self {
        Self {
            read: Mutex::new(Some(read)),
            write: Mutex::new(Some(write)),
        }
    }
}

#[async_trait]
impl<Read, Write> Transport for TransportStream<Read, Write>
where
    Read: AsyncReadExt + std::marker::Unpin + Send,
    Write: AsyncWriteExt + std::marker::Unpin + Send,
{
    async fn send(&self, request: Request) -> Result<()> {
        if let Some(write) = self.write.lock().await.as_mut() {
            // Serialize the request to a JSON string.
            let payload = serde_json::to_vec(&request)?;

            // Ensure the payload is not too large.
            assert!(payload.len() <= u32::MAX as usize);

            // Convert the payload length to a big-endian byte array.
            let payload_length: [u8; 4] = (payload.len() as u32).to_be_bytes();

            // Send the payload length to the server.
            write.write_all(&payload_length).await?;

            // Send the payload to the server.
            log::info!("Sending: {:?}", &request);
            write.write_all(&payload).await?;

            Ok(())
        } else {
            Err(Error::InvalidAgentConnection(
                "Disconnected stream".to_string(),
            ))
        }
    }

    async fn recv(&self) -> Result<Response> {
        if let Some(read) = self.read.lock().await.as_mut() {
            // Read the payload length from the server.
            let response_length: usize = read.read_u32().await?.try_into()?;

            // Allocate a buffer of that length.
            let mut buf = vec![0u8; response_length];

            // Read the payload
            read.read_exact(&mut buf).await?;

            let response: Response = serde_json::from_slice(&buf)?;

            log::info!("Receiving: {:?}", &response);

            // Deserialize the response from the JSON string.
            Ok(response)
        } else {
            Err(Error::InvalidAgentConnection(
                "Disconnected stream".to_string(),
            ))
        }
    }

    async fn close(&self) -> Result<()> {
        log::info!("TransportStream::close");

        // Only call shutdown if the stream has not already been closed down
        if let Some(mut write) = self.write.lock().await.take() {
            log::info!("TransportStream::close:send shutdown");

            // First explicitly signal the stream shutdown by sending
            // null character.
            write.shutdown().await?;
        }

        // Drop the read stream
        log::info!("TransportStream::close:drop read stream");
        self.read.lock().await.take();

        Ok(())
    }
}
