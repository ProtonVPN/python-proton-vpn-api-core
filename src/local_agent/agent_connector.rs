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
use super::{
    transport_playback::TransportPlayback, transport_stream::TransportStream,
    AgentConnection, Error, Result,
};

#[cfg(feature = "python")]
use super::{DEFAULT_TIMEOUT_IN_SECONDS, super::python::{await_py, future}};

#[cfg(feature = "python")]
use pyo3::prelude::*;
// -----------------------------------------------------------------------------
use rustls_pki_types::CertificateDer;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use x509_parser::time::ASN1Time;
// -----------------------------------------------------------------------------

/// The address of the local agent server, this ip is always the same
const SERVER_ADDR: &str = "10.2.0.1:65432";

/// The root certificate of the local agent server, this may expire in the future
/// we have a test in the gtk python application unit tests which will fail
/// when this expires.
const PROTON_VPN_ROOT_FOLLOWED_BY_INTERMEDIATE_LEGACY_CA: &str = r#"
-----BEGIN CERTIFICATE-----
MIIFnTCCA4WgAwIBAgIUCI574SM3Lyh47GyNl0WAOYrqb5QwDQYJKoZIhvcNAQEL
BQAwXjELMAkGA1UEBhMCQ0gxHzAdBgNVBAoMFlByb3RvbiBUZWNobm9sb2dpZXMg
QUcxEjAQBgNVBAsMCVByb3RvblZQTjEaMBgGA1UEAwwRUHJvdG9uVlBOIFJvb3Qg
Q0EwHhcNMTkxMDE3MDgwNjQxWhcNMzkxMDEyMDgwNjQxWjBeMQswCQYDVQQGEwJD
SDEfMB0GA1UECgwWUHJvdG9uIFRlY2hub2xvZ2llcyBBRzESMBAGA1UECwwJUHJv
dG9uVlBOMRowGAYDVQQDDBFQcm90b25WUE4gUm9vdCBDQTCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBAMkUT7zMUS5C+NjQ7YoGpVFlfbN9HFgG4JiKfHB8
QxnPPRgyTi0zVOAj1ImsRilauY8Ddm5dQtd8qcApoz6oCx5cFiiSQG2uyhS/59Zl
5wqIkw1o+CgwZgeWkq04lcrxhhfPgJZRFjrYVezy/Z2Ssd18s3/FFNQ+2iV1KC2K
z8eSPr50u+l9vEKsKiNGkJTdlWjoDKZM2C15i/h8Smi+PdJlx7WMTtYoVC1Fzq0r
aCPDQl18kspu11b6d8ECPWghKcDIIKuA0r0nGqF1GvH1AmbC/xUaNrKgz9AfioZL
MP/l22tVG3KKM1ku0eYHX7NzNHgkM2JKnBBannImQQBGTAcvvUlnfF3AHx4vzx7H
ahpBz8ebThx2uv+vzu8lCVEcKjQObGwLbAONJN2enug8hwSSZQv7tz7onDQWlYh0
El5fnkrEQGbukNnSyOqTwfobvBllIPzBqdO38eZFA0YTlH9plYjIjPjGl931lFAA
3G9t0x7nxAauLXN5QVp1yoF1tzXc5kN0SFAasM9VtVEOSMaGHLKhF+IMyVX8h5Iu
IRC8u5O672r7cHS+Dtx87LjxypqNhmbf1TWyLJSoh0qYhMr+BbO7+N6zKRIZPI5b
MXc8Be2pQwbSA4ZrDvSjFC9yDXmSuZTyVo6Bqi/KCUZeaXKof68oNxVYeGowNeQd
g/znAgMBAAGjUzBRMB0GA1UdDgQWBBR44WtTuEKCaPPUltYEHZoyhJo+4TAfBgNV
HSMEGDAWgBR44WtTuEKCaPPUltYEHZoyhJo+4TAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4ICAQBBmzCQlHxOJ6izys3TVpaze+rUkA9GejgsB2DZXIcm
4Lj/SNzQsPlZRu4S0IZV253dbE1DoWlHanw5lnXwx8iU82X7jdm/5uZOwj2NqSqT
bTn0WLAC6khEKKe5bPTf18UOcwN82Le3AnkwcNAaBO5/TzFQVgnVedXr2g6rmpp9
gdedeEl9acB7xqfYfkrmijqYMm+xeG2rXaanch3HjweMDuZdT/Ub5G6oir0Kowft
lA1ytjXRg+X+yWymTpF/zGLYfSodWWjMKhpzZtRJZ+9B0pWXUyY7SuCj5T5SMIAu
x3NQQ46wSbHRolIlwh7zD7kBgkyLe7ByLvGFKa2Vw4PuWjqYwrRbFjb2+EKAwPu6
VTWz/QQTU8oJewGFipw94Bi61zuaPvF1qZCHgYhVojRy6KcqncX2Hx9hjfVxspBZ
DrVH6uofCmd99GmVu+qizybWQTrPaubfc/a2jJIbXc2bRQjYj/qmjE3hTlmO3k7V
EP6i8CLhEl+dX75aZw9StkqjdpIApYwX6XNDqVuGzfeTXXclk4N4aDPwPFM/Yo/e
KnvlNlKbljWdMYkfx8r37aOHpchH34cv0Jb5Im+1H07ywnshXNfUhRazOpubJRHn
bjDuBwWS1/Vwp5AJ+QHsPXhJdl3qHc1szJZVJb3VyAWvG/bWApKfFuZX18tiI4N0
EA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFjDCCA3SgAwIBAgIBBDANBgkqhkiG9w0BAQsFADBeMQswCQYDVQQGEwJDSDEf
MB0GA1UECgwWUHJvdG9uIFRlY2hub2xvZ2llcyBBRzESMBAGA1UECwwJUHJvdG9u
VlBOMRowGAYDVQQDDBFQcm90b25WUE4gUm9vdCBDQTAeFw0yMjAxMTQxNjQ4MTBa
Fw0zMjAxMTIxNjQ4NDBaMEoxCzAJBgNVBAYTAkNIMRUwEwYDVQQKEwxQcm90b25W
UE4gQUcxJDAiBgNVBAMTG1Byb3RvblZQTiBJbnRlcm1lZGlhdGUgQ0EgMTCCAiIw
DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANv3uwQMFjYOx74taxadhczLbjCT
uT73jMz09EqFNv7O7UesXfYJ6kQgYV9YyE86znP4xbsswNUZYh+XdZUpOoP6Zu3t
R/iiYiuzi6jVYrJ66G89nPqS2mm5dn8Fbb8CRWkJygm8AdlYkDwYNldhDUrERlQd
CRDGsYYg/98dded+5pXnSG8Y/+iuLM6/YYhkUVQeCfq1L6XguSwu8CuvJjIjjE1P
ptUHa3Hc3tGziVydltKynxWlqb1dJqinGKiBZvYnoiV4motpFYwhc3Wd09JLPzeo
bhD2IAZ2evSatikMWDingEv1EJXpI+V/E2AK3xHKSkhw+YZx99tNxCiOu3U5BFAr
eZR3j2YnZzX1nEv9p02IGaWzzYJPNED0zSO2w07uthSmKcxA39VTvs91lptbcV7V
TxoJY0SErHIeVS3Scrnr7WvoOTuu3M3SCRqe6oI9oJZMOdfNsceBdvG+qlpOFICo
BjO53W4BK8KahzTd/PWlBRiVJ3UVv8xXwUDA+o9834DXVAobaAHXQtM9jNobqT98
FXhZktjOQEA2UORL581ZPxfKeHLRcgWJ5dmPsDBGy/L6/qW/yrm6DUDAdN5+q41+
gSNEjNBjLBJQFUmDk3l6Qxiu0uEDQ98oFvGHk5US2Kbj0OAq1RpiDjHci/536yua
9rTC+cxekTM2asdXAgMBAAGjaTBnMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8E
CDAGAQH/AgEAMB8GA1UdIwQYMBaAFHjha1O4QoJo89SW1gQdmjKEmj7hMCAGA1Ud
JQEB/wQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAgEA
fFMtLGksBmCWBbLu5SJW+6/8EtOoGD+QbCRc7kCpsKZOqgwKuVeEQHsTCJgeSyWM
XXnD5mqtEKcgaJ8bjgE2YkPPajiqnqAYPxJ4xCUXELY+Tm6LMifAuxtGIC9M04Cy
IIe44OtblEQDP+JB++TLKbwnj/+TAC7537eGxZa3Jesc4YUD2qUTp2Zqqo2Tzqib
iyuGCeVfc+OiG0xcZls9lvYOIAcEIqxvWEwgSCJUul1567b3/mKe5S2SkpY6du29
I3k3qhvSvrA1WtBlqAAeggLiQ5DE47LIMdJU+roYmk4TAJmibI2nKoonf1+OBF/S
Zg04xEd18dtAoX1CjgTHlIeNQzeGV6O0/jhn3BfNWB2a2A8u5mVxDyOG3ZJEjdKC
eiv6r/iEGI7BwOe3WSdvcmNpsa+UehbupN9azRyhEykXmG+LGF5DEylLxK128tdD
0rl3p1qEWcRYIdzE8iS7rp0y0wD0pz0ye80OyGXJYc3Y8WSxPVQL/t35x7gaKnIW
8S0Goqe7Or/F3bxYXh+kk1ARZyF0bmH/yOlkstV7ETsL7OB8aDEvlc/BG80bU68m
cQDquPP1RszuksYu6pGZPtwra23Wuo8alsxVg4aJhhIKP/iocJdWKnodMMAIF23N
+WPATcqIu3YrtUFWnNHGAa/z3xBx3VwPMGIOcmfVl4E=
-----END CERTIFICATE-----
"#;

// -----------------------------------------------------------------------------

/// Parameters for connecting to the local agent server.
/// # Fields
///
/// * `domain` - The name of the local agent server to connect to.
/// * `key` - The private key pks8 formatted in pem encoding.
/// * `cert` - The certificate in pem encoding.
/// * `timeout_in_seconds` - The timeout in seconds for the connection.
///
#[derive(Debug)]
#[cfg_attr(feature = "python", pyo3::pyclass)]
pub struct ConnectParams {
    pub domain: String,
    pub key: String,
    pub cert: String,
    pub timeout_in_seconds: u64,
}

/// Builds the root certificate store, from the constant PROTON_VPN_ROOT_FOLLOWED_BY_INTERMEDIATE_LEGACY_CA.
fn build_root_cert_store() -> Result<RootCertStore> {
    let mut cursor = std::io::Cursor::new(
        PROTON_VPN_ROOT_FOLLOWED_BY_INTERMEDIATE_LEGACY_CA
    );
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

fn ensure_certificates_are_current(
    certificates: &[CertificateDer<'_>],
    now: Option<ASN1Time>,  // Optional time for testing
) -> Result<()> {
    let now = now.unwrap_or_else(ASN1Time::now);

    for cert_d in certificates {

        let (_, cert) = x509_parser::parse_x509_certificate(cert_d).map_err(
            |_| Error::UnableToParseCertificate,
        )?;

        let validity = &cert.tbs_certificate.validity;

        // Check if current time is before the certificate's start time
        if now < validity.not_before {
            return Err(Error::NotYetValidCertificate(format!(
                "Now {:?}, Start: {}, End: {}",
                now, &validity.not_before, &validity.not_after
            )));
        }

        // Check if current time is after the certificate's end time
        if now > validity.not_after {
            return Err(Error::ExpiredCertificate(format!(
                "Now {:?}, Start: {}, End: {}",
                now, &validity.not_before, &validity.not_after
            )));
        }
    }

    Ok(())
}

/// Creator of AgentConnections.
///
/// You should only need one of these per application.
/// see AgentConnector::connect
#[cfg_attr(feature = "python", pyo3::pyclass)]
#[derive(Clone)]
pub struct AgentConnector {}

impl AgentConnector {
    /// Connects to the LocalAgent server.
    ///
    /// Returns an AgentConnection if successful.
    ///
    /// # Arguments
    ///
    /// * `params` - The parameters to establish the agent connection.
    ///
    pub async fn connect(
        params: ConnectParams
    ) -> Result<AgentConnection> {
        // Build the root certificate store
        let root_cert_store = build_root_cert_store()?;

        let certs = parse_certificates(&params.cert)?;

        // This does a time validation of the certificates
        // and will return an error if any of them are expired.
        ensure_certificates_are_current(&certs, None)?;

        // Key is in pks8 format
        let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(&params.key))?
            .ok_or(Error::NoPrivateKeyFound)?;

        let config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_client_auth_cert(certs, key)?;

        let connector = TlsConnector::from(Arc::new(config));
        let dnsname =
            rustls_pki_types::ServerName::try_from(params.domain.clone())?;

        let timeout_duration =
            std::time::Duration::from_secs(params.timeout_in_seconds);

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
#[cfg(feature = "python")]
#[pyo3::pymethods]
impl AgentConnector {
    /// Creates a new AgentConnector.
    #[new]
    pub fn new() -> PyResult<Self> {
        Ok(Self {})
    }

    /// Connects to the LocalAgent server.
    ///
    /// This is an async function, and will return a future that will resolve
    /// to an AgentConnection.
    ///
    /// # Arguments
    ///
    /// * `domain` - The name of the local agent server to connect to as a string.
    /// * `key` - The private key pks8 formatted in pem encoding as a string.
    /// * `cert` - The certificate in pem encoding as a string.
    /// * `timeout` - Optional timeout used to stablish the connection.
    ///
    #[pyo3(name="connect", signature = (domain, key, cert, timeout_in_seconds=DEFAULT_TIMEOUT_IN_SECONDS))]
    pub fn py_connect<'p>(
        &self,
        py: Python<'p>,
        domain: String,
        key: String,
        cert: String,
        timeout_in_seconds: u64,
    ) -> PyResult<Bound<'p, PyAny>> {
        await_py!(py, Self::connect(ConnectParams {
            domain,
            key,
            cert,
            timeout_in_seconds,
        }))
    }

    /// Reads a string of json containing responses and returns an
    /// AgentConnection object, which behaves like a real connection.
    ///
    /// This is an async function, and will return a future that will resolve
    /// to an AgentConnection.
    ///
    /// # Arguments
    ///
    /// * `responses` - A string of json containing responses.
    ///
    #[pyo3(name="playback", signature = (responses))]
    pub fn py_playback<'p>(
        &self,
        py: Python<'p>,
        responses: String,
    ) -> PyResult<Bound<'p, PyAny>> {
        await_py!(py, Self::playback(&responses))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn test_proton_vpn_root_and_intermediate_legacy_certificates_are_not_close_to_expiration() {
        // Ensure that the certificate still has 90 days before it expires.
        let ninety_days = 90_f64;

        // 90 days in seconds
        let seconds = ninety_days * 24_f64 * 60_f64 * 60_f64;

        // We need an in-memory reader for the certificate as we are reading
        // an in-memory hard coded certificate.
        let mut reader = std::io::Cursor::new(
            PROTON_VPN_ROOT_FOLLOWED_BY_INTERMEDIATE_LEGACY_CA
        );

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

    // Testing certificate validity errors with the embedded root/intermediate certificates

    // Root CA: Valid 2019-01-17 - 2039-01-12
    // Intermediate: Valid 2022-01-14 - 2032-01-12

    fn parse_embedded_certificates() -> Vec<CertificateDer<'static>> {
        let mut cursor = std::io::Cursor::new(
            PROTON_VPN_ROOT_FOLLOWED_BY_INTERMEDIATE_LEGACY_CA
        );
        rustls_pemfile::certs(&mut cursor)
            .filter_map(|x| x.ok())
            .collect()
    }

    #[test]
    fn test_valid_certificate_with_current_time() {
        let certs = parse_embedded_certificates();

        // Use current time
        let result = ensure_certificates_are_current(&certs, None);
        assert!(result.is_ok(), "Embedded certificates should be currently valid");
    }

    #[test]
    fn test_expired_certificate_error() {
        let certs = parse_embedded_certificates();
        // Time after both certificates end
        let expired_time = ASN1Time::new(datetime!(2040-01-15 00:00:00 UTC));
        let result = ensure_certificates_are_current(&certs, Some(expired_time));
        assert!(matches!(result, Err(Error::ExpiredCertificate(_))),
                "Should return ExpiredCertificate error when time is past certificate end date");
    }

    #[test]
    fn test_not_yet_valid_certificate_error() {
        let certs = parse_embedded_certificates();

        // Time before the root cert starts (with buffer)
        let not_yet_valid_time = ASN1Time::new(datetime!(2019-01-01 00:00:00 UTC));

        let result = ensure_certificates_are_current(&certs, Some(not_yet_valid_time));
        assert!(matches!(result, Err(Error::NotYetValidCertificate(_))),
                "Should return NotYetValidCertificate error when time is before certificate start date");
    }

}
