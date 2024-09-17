// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use crate::{
    transport_playback::TransportPlayback, transport_stream::TransportStream,
    AgentConnection, Error, Result,
};
// -----------------------------------------------------------------------------
use rustls_pki_types::CertificateDer;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{version::TLS12, ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
// -----------------------------------------------------------------------------

/// The address of the local agent server, this ip is always the same
const SERVER_ADDR: &str = "10.2.0.1:65432";

/// The root certificate of the local agent server, this may expire in the future
/// we have a test in the gtk python application unit tests which will fail
/// when this expires.
const PROTON_VPN_ROOT_CA: &str = r#"-----BEGIN CERTIFICATE-----
MIIFozCCA4ugAwIBAgIBATANBgkqhkiG9w0BAQ0FADBAMQswCQYDVQQGEwJDSDEV
MBMGA1UEChMMUHJvdG9uVlBOIEFHMRowGAYDVQQDExFQcm90b25WUE4gUm9vdCBD
QTAeFw0xNzAyMTUxNDM4MDBaFw0yNzAyMTUxNDM4MDBaMEAxCzAJBgNVBAYTAkNI
MRUwEwYDVQQKEwxQcm90b25WUE4gQUcxGjAYBgNVBAMTEVByb3RvblZQTiBSb290
IENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAt+BsSsZg7+AuqTq7
vDbPzfygtl9f8fLJqO4amsyOXlI7pquL5IsEZhpWyJIIvYybqS4s1/T7BbvHPLVE
wlrq8A5DBIXcfuXrBbKoYkmpICGc2u1KYVGOZ9A+PH9z4Tr6OXFfXRnsbZToie8t
2Xjv/dZDdUDAqeW89I/mXg3k5x08m2nfGCQDm4gCanN1r5MT7ge56z0MkY3FFGCO
qRwspIEUzu1ZqGSTkG1eQiOYIrdOF5cc7n2APyvBIcfvp/W3cpTOEmEBJ7/14RnX
nHo0fcx61Inx/6ZxzKkW8BMdGGQF3tF6u2M0FjVN0lLH9S0ul1TgoOS56yEJ34hr
JSRTqHuar3t/xdCbKFZjyXFZFNsXVvgJu34CNLrHHTGJj9jiUfFnxWQYMo9UNUd4
a3PPG1HnbG7LAjlvj5JlJ5aqO5gshdnqb9uIQeR2CdzcCJgklwRGCyDT1pm7eoiv
WV19YBd81vKulLzgPavu3kRRe83yl29It2hwQ9FMs5w6ZV/X6ciTKo3etkX9nBD9
ZzJPsGQsBUy7CzO1jK4W01+u3ItmQS+1s4xtcFxdFY8o/q1zoqBlxpe5MQIWN6Qa
lryiET74gMHE/S5WrPlsq/gehxsdgc6GDUXG4dk8vn6OUMa6wb5wRO3VXGEc67IY
m4mDFTYiPvLaFOxtndlUWuCruKcCAwEAAaOBpzCBpDAMBgNVHRMEBTADAQH/MB0G
A1UdDgQWBBSDkIaYhLVZTwyLNTetNB2qV0gkVDBoBgNVHSMEYTBfgBSDkIaYhLVZ
TwyLNTetNB2qV0gkVKFEpEIwQDELMAkGA1UEBhMCQ0gxFTATBgNVBAoTDFByb3Rv
blZQTiBBRzEaMBgGA1UEAxMRUHJvdG9uVlBOIFJvb3QgQ0GCAQEwCwYDVR0PBAQD
AgEGMA0GCSqGSIb3DQEBDQUAA4ICAQCYr7LpvnfZXBCxVIVc2ea1fjxQ6vkTj0zM
htFs3qfeXpMRf+g1NAh4vv1UIwLsczilMt87SjpJ25pZPyS3O+/VlI9ceZMvtGXd
MGfXhTDp//zRoL1cbzSHee9tQlmEm1tKFxB0wfWd/inGRjZxpJCTQh8oc7CTziHZ
ufS+Jkfpc4Rasr31fl7mHhJahF1j/ka/OOWmFbiHBNjzmNWPQInJm+0ygFqij5qs
51OEvubR8yh5Mdq4TNuWhFuTxpqoJ87VKaSOx/Aefca44Etwcj4gHb7LThidw/ky
zysZiWjyrbfX/31RX7QanKiMk2RDtgZaWi/lMfsl5O+6E2lJ1vo4xv9pW8225B5X
eAeXHCfjV/vrrCFqeCprNF6a3Tn/LX6VNy3jbeC+167QagBOaoDA01XPOx7Odhsb
Gd7cJ5VkgyycZgLnT9zrChgwjx59JQosFEG1DsaAgHfpEl/N3YPJh68N7fwN41Cj
zsk39v6iZdfuet/sP7oiP5/gLmA/CIPNhdIYxaojbLjFPkftVjVPn49RqwqzJJPR
N8BOyb94yhQ7KO4F3IcLT/y/dsWitY0ZH4lCnAVV/v2YjWAWS3OWyC8BFx/Jmc3W
DK/yPwECUcPgHIeXiRjHnJt0Zcm23O2Q3RphpU+1SO3XixsXpOVOYP6rJIXW9bMZ
A1gTTlpi7A==
-----END CERTIFICATE-----
"#;

// -----------------------------------------------------------------------------

/// Builds the root certificate store, fom the constant PROTON_VPN_ROOT_CA.
fn build_root_cert_store() -> Result<RootCertStore> {
    let mut cursor = std::io::Cursor::new(PROTON_VPN_ROOT_CA);
    let ca = rustls_pemfile::certs(&mut cursor);
    let mut root_cert_store = RootCertStore::empty();
    for i in ca {
        root_cert_store.add(i?)?;
    }
    Ok(root_cert_store)
}

/// Parses the given pem file of certificates and returns a vector of
/// valid certificates.
fn parse_certificates(cert: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = std::io::Cursor::new(cert);
    let certs = rustls_pemfile::certs(&mut cursor)
        .filter_map(|x| x.ok())
        .collect::<Vec<CertificateDer<'static>>>();

    if certs.is_empty() {
        return Err(Error::NoCertificatesFound);
    }

    Ok(certs)
}

/// Creator of AgentConnections.
///
/// You should only need one of these per application.
/// see AgentConnector::connect
#[derive(Clone)]
pub struct AgentConnector {}

impl AgentConnector {
    /// Connects to the LocalAgent server.
    ///
    /// Returns an AgentConnection if successful.
    ///
    /// # Arguments
    ///
    /// * `domain` - The name of the local agent server to connect to.
    /// * `key` - The private key pks8 formatted in pem encoding.
    /// * `cert` - The certificate in pem encoding.
    /// * `timeout_in_seconds` - The timeout in seconds for the connection.
    ///
    pub async fn connect(
        domain: &str,
        key: &str,
        cert: &str,
        timeout_in_seconds: u64,
    ) -> Result<AgentConnection> {
        // Build the root certificate store
        let root_cert_store = build_root_cert_store()?;

        let certs = parse_certificates(cert)?;

        // Key is in pks8 format
        let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(key))?
            .ok_or(Error::NoPrivateKeyFound)?;

        // TLS 1.2 is forced because with 1.3 we were not getting any errors
        // when later we were establishing a connection with an expired certificate.
        // FIX-ME: see how to achieve the same with 1.3
        let config = ClientConfig::builder_with_protocol_versions(&[&TLS12])
            .with_root_certificates(root_cert_store)
            .with_client_auth_cert(certs, key)?;

        let connector = TlsConnector::from(Arc::new(config));
        let dnsname =
            rustls_pki_types::ServerName::try_from(domain.to_string())?;

        let timeout_duration =
            std::time::Duration::from_secs(timeout_in_seconds);

        let tcp_stream = tokio::time::timeout(
            timeout_duration,
            TcpStream::connect(SERVER_ADDR),
        )
        .await??;

        let mut ka = socket2::TcpKeepalive::new();
        ka = ka.with_time(std::time::Duration::from_secs(60));
        ka = ka.with_interval(std::time::Duration::from_secs(30));
        ka = ka.with_retries(3);
        let sock_ref = socket2::SockRef::from(&tcp_stream);
        sock_ref.set_tcp_keepalive(&ka)?;

        let connection = tokio::time::timeout(
            timeout_duration,
            connector.connect(dnsname, tcp_stream),
        )
        .await??;

        let (read, write) = tokio::io::split(connection);

        AgentConnection::new(TransportStream::new(read, write))
    }

    /// Reads a json of server Responses and returns an AgentConnection which
    /// will behave like a connection to the local agent server, but will just
    /// play back the responses from the json.
    ///
    /// Returns an AgentConnection if successful.
    ///
    /// # Arguments
    ///
    /// * `responses` - A string containing the responses that the Mock server.
    ///
    pub async fn playback(responses: &str) -> Result<AgentConnection> {
        AgentConnection::new(TransportPlayback::new(responses)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proton_vpn_root_certificate_is_not_close_to_expiration() {
        // Ensure that the certificate still has 90 days before it expires.
        let ninety_days = 90_f64;

        // 90 days in seconds
        let seconds = ninety_days * 24_f64 * 60_f64 * 60_f64;

        // We need an in-memory reader for the certificate as we are reading
        // an in-memory hard coded certificate.
        let mut reader = std::io::Cursor::new(PROTON_VPN_ROOT_CA);

        // Find the certificate in the pem file
        for cert_der in rustls_pemfile::certs(&mut reader) {
            // Ensure that we have found the certificate
            let cert_i = cert_der.expect("Failed to get certificate");

            // Parse the certificate so we can get the expiration date from it
            let cert = x509_parser::parse_x509_certificate(&(cert_i))
                .expect("Certificate does not parse");

            // Get the expiration date of the certificate in seconds
            let expires_in = cert
                .1
                .tbs_certificate
                .validity
                .time_to_expiration()
                .expect("Failed to get expiration date")
                .as_seconds_f64();

            // Compare this against a minimum of 90 days
            assert!(expires_in > seconds);
        }
    }
}
