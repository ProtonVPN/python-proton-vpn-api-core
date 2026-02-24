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
/// This module provides the ability to request port forwarding from the proton
/// vpn NAT-PMP gateway.
///
/// The NAT-PMP protocol is used to request port forwarding from a NAT gateway.
/// This is useful when a device is behind a NAT gateway and needs to receive
/// incoming connections.
///
/// This will only work if the proton vpn client is running and connected to
/// a proton vpn server.
///
/// Its not possible to choose the external port, the proton vpn gateway will
/// choose the external port, it's also not possible to choose the internal port,
/// the internal port is the same as the external port.
///
/// This module supports both udp and tcp port forwarding.
///
/// Details of nat-pmp protocol can be found here
/// http://miniupnp.free.fr/nat-pmp.html
///
use super::error::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// We want to display logs when running tests, but log module doesnt work in
// tests. So we use println! for logs in tests.
mod log {
    #[cfg(not(test))]
    pub use ::log::info; // Use log crate when building application

    #[cfg(test)]
    pub use std::println as info; // Workaround to use prinltn! for logs.
}

const NAT_PMP_ADDRESS: &str = "10.2.0.1:5351";
const PROTOCOL_VERSION_NATPMP: u8 = 0;
const DEFAULT_PORT_LIFETIME: u32 = 60;

/// The different types of NAT-PMP request operations that can be made.
#[repr(u8)]
#[derive(Clone)]
pub enum NatPmpRequestOp {
    #[allow(dead_code)]
    ExternalAddress = 0,
    #[allow(dead_code)]
    Udp = 1,
    Tcp = 2,
}

/// The different types of NAT-PMP response operations that can be received.
#[repr(u8)]
pub enum NatPmpReplyOp {
    Udp = 129,
    Tcp = 130,
}

/// The different types of NAT-PMP response codes that can be received, these
/// are either success or an error code.
#[repr(u16)]
#[derive(Debug)]
pub enum NatPmpResponseCode {
    Success, // 0
    #[allow(dead_code)]
    UnsupportedVersion, // 1
    #[allow(dead_code)]
    NotAuthorized, // 2
    #[allow(dead_code)]
    NetworkFailure, // 3
    #[allow(dead_code)]
    OutOfResources, // 4
    #[allow(dead_code)]
    UnsupportedOpcode, // 5
}

/// The request struct that is sent to the NAT-PMP gateway.
#[derive(Serialize, Deserialize, Debug)]
struct Request {
    version: u8, // The version of the protocol. 0 for NAT-PMP, 1 for PCP.
    operation: u8, // The operation to perform, see NatPmpRequestOp.
    reserved: u16, // Reserved field, must be 0.
    internal_port: u16, // The internal (client) port.
    external_port: u16, // The external (server ) port.
    lifetime_seconds: u32, // The lifetime of the port forwarding in seconds.
}

impl Request {
    pub fn new(operation: NatPmpRequestOp) -> Self {
        Request {
            version: PROTOCOL_VERSION_NATPMP,
            operation: operation as u8,
            reserved: 0,
            internal_port: 0,
            external_port: 0,
            lifetime_seconds: DEFAULT_PORT_LIFETIME,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    version: u8, // The version of the protocol. 0 for NAT-PMP, 1 for PCP.
    operation: u8, // The operation that was performed, see NatPmpReplyOp.
    response_code: u16, // The status of the requested operation, see NatPmpResponseCode.
    gateway_epoch_seconds: u32, // Seconds since port mapping table was initialized
    internal_port: u16,         // The internal (client) port.
    external_port: u16,         // The external (server) port.
    lifetime_seconds: u32, // The lifetime of this new port forwarding in seconds.
}

/// This is an abstraction for the network transport used by the port mapping
/// module.
/// Creating an abstraction allows us to mock the transport layer and test
/// the module.
#[async_trait]
pub trait PortForwardingTransport {
    async fn send(&self, request: &[u8]) -> Result<()>;
    async fn recv(&self) -> Result<[u8; 16]>;
}

/// This is the udp based implementation of the PortForwardingTransport,
/// which is what we use in production.
struct NetworkTransport {
    socket: tokio::net::UdpSocket,
}

impl NetworkTransport {
    pub async fn connect_to_nmap_server() -> Result<Self> {
        let socket = tokio::net::UdpSocket::bind(std::net::SocketAddr::V4(
            std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
        ))
        .await?;

        socket.connect(NAT_PMP_ADDRESS).await?;

        Ok(Self { socket })
    }
}

/// Implement the PortForwardingTransport trait for NetworkTransport.
/// This allows the request_port_forwarding function to use the NetworkTransport
/// to send and receive messages over a udp socket
#[async_trait]
impl PortForwardingTransport for NetworkTransport {
    async fn send(&self, request: &[u8]) -> Result<()> {
        self.socket.send(request).await?;
        Ok(())
    }

    async fn recv(&self) -> Result<[u8; 16]> {
        const BYTE_SIZE: usize = std::mem::size_of::<Response>();
        static_assertions::const_assert_eq!(BYTE_SIZE, 16);

        let mut response_bytes = [0_u8; 16];
        let bytes_read = self.socket.recv(&mut response_bytes).await?;

        if bytes_read != BYTE_SIZE {
            return Err(Error::PortForwarding(format!(
                "Protocol error incorrect number of bytes returned in \
                         nat-pmp response {}",
                bytes_read
            )));
        }

        Ok(response_bytes)
    }
}

/// Request a UDP port forwarding from the NAT-PMP gateway.
/// Returns the internal port that was mapped.
/// The external (server) port is chosen by the gateway and is the same as
/// the internal (client) port.
///
/// If the port forwarding fails, an error is returned.
///
async fn request_port_forwarding(
    transport: &impl PortForwardingTransport,
    operation: NatPmpRequestOp,
    timeout_in_seconds: u64,
    max_retries: u32,
) -> Result<u16> {
    let mut timeout_duration =
        std::time::Duration::from_secs(timeout_in_seconds);

    use bincode::Options as _;

    let serializer = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_big_endian();

    let request = Request::new(operation.clone());
    let request_u8: Vec<u8> = serializer.serialize(&request)?;

    for attempt in 0..max_retries + 1 {
        log::info!("Sending {:?} attempt {}", &request, attempt);

        // We use tokio::time::timeout to set a timeout on the send
        // because send can block in cases where routing to the destination
        // fails.
        //
        // Send could also block if the output buffer is full, but we are
        // sending a small message so this is unlikely.
        //
        // We want a timeout on send to actually fail, we don't want to rety
        // the send.
        tokio::time::timeout(
            timeout_duration,
            transport.send(&request_u8.clone()),
        )
        .await??;

        // We're putting a timeout on recv because the sent message could be
        // dropped at any point in the network, so we want to timeout and retry
        // the send and recv.
        //
        // The only guarantee that we have that the send was successful is that
        // we get a response.
        match tokio::time::timeout(timeout_duration, transport.recv()).await {
            Ok(Ok(response_u8)) => {
                let response: Response =
                    serializer.deserialize(&response_u8)?;

                log::info!("Receiving {:?}", response);

                if response.response_code != NatPmpResponseCode::Success as u16
                {
                    return Err(Error::PortForwarding(format!(
                        "Failed to request port forwarding, response code: {}",
                        response.response_code
                    )));
                }

                type Req = NatPmpRequestOp;
                type Rep = NatPmpReplyOp;
                match operation {
                    Req::Tcp if response.operation == Rep::Tcp as u8 => (),
                    Req::Udp if response.operation == Rep::Udp as u8 => (),
                    _ => {
                        return Err(Error::PortForwarding(format!(
                            "Failed to request port forwarding, unexpected response code: {}",
                            response.response_code
                        )));
                    }
                }

                return Ok(response.internal_port);
            }
            Err(_elapsed) => {
                timeout_duration *= 2;
                log::info!(
                    "Hit timeout, retrying with longer timeout {:?}",
                    timeout_duration
                );
            }
            Ok(Err(e)) => return Err(e),
        }
    }

    Err(Error::PortForwarding(
        "Exhausted maximum retries".to_string(),
    ))
}

/// Request a UDP port forwarding from the NAT-PMP gateway.
/// Returns the internal port that was mapped.
/// The external (server) port is chosen by the gateway and is the same as
/// the internal (client) port.
///
/// If the port forwarding fails, an error is returned.
///
pub async fn request_tcp_port_forwarding(
    timeout_in_seconds: u64,
    max_retries: u32,
) -> Result<u16> {
    // Create the network transport object
    let transport = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_in_seconds),
        NetworkTransport::connect_to_nmap_server(),
    )
    .await??;

    // Request the port forwarding
    request_port_forwarding(
        &transport,
        NatPmpRequestOp::Tcp,
        timeout_in_seconds,
        max_retries,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockNetworkTransport {
        response: [u8; 16],
    }

    #[async_trait]
    impl PortForwardingTransport for MockNetworkTransport {
        async fn send(&self, request: &[u8]) -> Result<()> {
            assert_eq!(request.len(), 12);
            // Version
            assert_eq!(request[0], PROTOCOL_VERSION_NATPMP);
            // Operation
            assert_eq!(request[1], NatPmpRequestOp::Tcp as u8);
            // Reserved
            assert_eq!(u16::from_be_bytes([request[2], request[3]]), 0_u16);
            // Internal port
            assert_eq!(u16::from_be_bytes([request[4], request[5]]), 0_u16);
            // External port
            assert_eq!(u16::from_be_bytes([request[6], request[7]]), 0_u16);
            // // Lifetime
            assert_eq!(
                u32::from_be_bytes([
                    request[8],
                    request[9],
                    request[10],
                    request[11]
                ]),
                DEFAULT_PORT_LIFETIME
            );

            Ok(())
        }

        async fn recv(&self) -> Result<[u8; 16]> {
            Ok(self.response.clone())
        }
    }

    // Launches async runtime for test
    #[tokio::test]
    async fn test_request_port_forwarding() -> Result<()> {
        use bincode::Options as _;

        let serializer = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_big_endian();

        let response = serializer.serialize(&Response {
            version: PROTOCOL_VERSION_NATPMP,
            operation: NatPmpReplyOp::Tcp as u8,
            response_code: NatPmpResponseCode::Success as u16,
            gateway_epoch_seconds: 1234_u32,
            internal_port: 123_u16,
            external_port: 456_u16,
            lifetime_seconds: 5678_u32,
        })?;

        use std::convert::TryInto as _;
        let mock_transport = MockNetworkTransport {
            response: response.try_into().expect("Unable to convert response"), // nosemgrep: panic-in-function-returning-result
        };

        assert_eq!(
            request_port_forwarding(
                &mock_transport,
                NatPmpRequestOp::Tcp,
                2,
                3,
            )
            .await?,
            123_u16
        );

        Ok(())
    }

    // Launches async runtime for test
    #[tokio::test]
    async fn test_failed_port_forwarding() -> Result<()> {
        use bincode::Options as _;

        let serializer = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_big_endian();

        let response = serializer.serialize(&Response {
            version: PROTOCOL_VERSION_NATPMP,
            operation: NatPmpReplyOp::Tcp as u8,
            response_code: NatPmpResponseCode::OutOfResources as u16,
            gateway_epoch_seconds: 0_u32,
            internal_port: 0_u16,
            external_port: 0_u16,
            lifetime_seconds: 0_u32,
        })?;

        use std::convert::TryInto as _;
        let mock_transport = MockNetworkTransport {
            response: response.try_into().expect("Unable to convert response"), // nosemgrep: panic-in-function-returning-result
        };

        match request_port_forwarding(
            &mock_transport,
            NatPmpRequestOp::Tcp,
            2,
            3,
        )
        .await
        {
            Err(Error::PortForwarding(e)) => {
                assert_eq!(
                    e,
                    "Failed to request port forwarding, response code: 4"
                );
            }
            _ => assert!(false),
        }

        Ok(())
    }

    // Uncomment this test to manually test port forwarding in a vpn environment

    // // Launches async runtime for test
    // #[tokio::test]
    // async fn test_real_port_forwarding() -> Result<()> {
    //     request_port_forwarding(
    //         &NetworkTransport::connect_to_nmap_server().await?,
    //         NatPmpRequestOp::Tcp,
    //         2,
    //         3,
    //     )
    //     .await?;

    //     Ok(())
    // }
}
