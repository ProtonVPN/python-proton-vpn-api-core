// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use crate::ErrorMessage;
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
}

pub type Result<T> = std::result::Result<T, Error>;
