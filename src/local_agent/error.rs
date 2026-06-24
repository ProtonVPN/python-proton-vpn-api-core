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
use super::ErrorMessage;
use thiserror::Error;
// -----------------------------------------------------------------------------
#[derive(Error, Debug, Default)]
pub enum Error {
    #[default]
    #[error("Default error")]
    Default,
    #[error("Tokio IO error: {0}")]
    Tokio(#[from] tokio::io::Error),
    #[error("Tokio Rustls error: {0}")]
    TokioRustls(#[from] tokio_rustls::rustls::Error),
    #[error("No certificates found")]
    NoCertificatesFound,
    #[error("No private key found")]
    NoPrivateKeyFound,
    #[error("No status from local agent")]
    NoStatusReturned,
    #[error("No more responses")]
    NoMoreResponses,
    #[error("Error received from local agent server")]
    GetStatusError(ErrorMessage),
    #[error("Invalid DNS name")]
    InvalidDnsNameError(#[from] rustls_pki_types::InvalidDnsNameError),
    #[error("An error from utf 8 conversion")]
    Utf8Error(#[from] std::str::Utf8Error),
    #[error("An error from json conversion")]
    JsonError(#[from] serde_json::Error),
    #[error("An error from int type conversion")]
    IntError(#[from] std::num::TryFromIntError),
    #[error("Tokio elapsed error: {0}")]
    TokioElapsed(#[from] tokio::time::error::Elapsed),
    #[error("Invalid agent connection: {0}")]
    InvalidAgentConnection(String),
    #[error("Port Forwarding: {0}")]
    PortForwarding(String),
    #[error("Bincode: {0}")]
    BincodeError(#[from] bincode::Error),
    #[error("Expired certificate: {0}")]
    ExpiredCertificate(String),
    #[error("Certificate not yet valid: {0}")]
    NotYetValidCertificate(String),
    #[error("Unable to parse certificate")]
    UnableToParseCertificate,
}

#[cfg(feature = "python")]
impl std::convert::From<Error> for pyo3::PyErr {
    fn from(err: Error) -> pyo3::PyErr {
        const FEATURE_ERROR_RANGE: std::ops::Range<u32> = 86200..86300;

        use super::python;

        match err {
            Error::ExpiredCertificate(e) =>
                python::ExpiredCertificateError::new_err(format!("{:?}", e)),
            Error::NotYetValidCertificate(e) =>
                python::NotYetValidCertificateError::new_err(format!("{:?}", e)),
            Error::Tokio(e)
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::BrokenPipe =>
            {
                pyo3::exceptions::PyTimeoutError::new_err(format!("{:?}", e))
            }
            Error::TokioElapsed(e) => {
                pyo3::exceptions::PyTimeoutError::new_err(format!("{:?}", e))
            }
            Error::GetStatusError(e) => {
                let error_message = format!("{:?}", e);

                // Check if the error is due to a policy error or an invalid
                // syntax error
                if FEATURE_ERROR_RANGE.contains(&e.code) {
                    let error_type = e.code % 5;
                    match error_type {
                        0 | 1 => return python::PolicyAPIError::new_err(error_message),
                        2 => return python::SyntaxAPIError::new_err(error_message),
                        _ => (),
                    }
                }

                // Otherwise, return a generic API error
                python::APIError::new_err(error_message)
            }
            _ => python::LocalAgentError::new_err(format!("{:?}", err)),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;


