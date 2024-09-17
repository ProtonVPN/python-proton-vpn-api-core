// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use local_agent_rs as la;

use crate::{
    APIError, ExpiredCertificateError, LocalAgentError, PolicyAPIError,
    SyntaxAPIError,
};
use pyo3::exceptions::PyTimeoutError;
use pyo3::PyErr;
use std::fmt::Write;
use std::io::ErrorKind;

use thiserror::Error;
// -----------------------------------------------------------------------------
#[derive(Error, Debug)]
pub enum Error {
    #[error("Local agent error: {0}")]
    LocalAgent(#[from] la::Error),
}

fn convert_error_message_string<T: std::fmt::Debug>(error: &T) -> String {
    let mut error_message = String::new();
    writeln!(&mut error_message, "{:?}", &error)
        .expect("Unable to write to error string");

    error_message
}

fn convert_to_default_error<T: std::fmt::Debug>(error: &T) -> PyErr {
    LocalAgentError::new_err(convert_error_message_string(&error))
}

const FEATURE_ERROR_RANGE: std::ops::Range<u32> = 86200..86300;

impl std::convert::From<Error> for PyErr {
    fn from(err: Error) -> PyErr {
        match err {
            Error::LocalAgent(la::Error::Tokio(e))
                if e.kind() == ErrorKind::InvalidData =>
            {
                ExpiredCertificateError::new_err(convert_error_message_string(
                    &e,
                ))
            }

            Error::LocalAgent(la::Error::Tokio(e))
                if e.kind() == ErrorKind::TimedOut =>
            {
                PyTimeoutError::new_err(convert_error_message_string(&e))
            }
            Error::LocalAgent(la::Error::TokioElapsed(e)) => {
                PyTimeoutError::new_err(convert_error_message_string(&e))
            }
            Error::LocalAgent(la::Error::GetStatusError(e)) => {
                let error_message = convert_error_message_string(&e);

                // Check if the error is due to a policy error or an invalid
                // syntax error
                if FEATURE_ERROR_RANGE.contains(&e.code) {
                    let error_type = e.code % 5;
                    match error_type {
                        0 | 1 => return PolicyAPIError::new_err(error_message),
                        2 => return SyntaxAPIError::new_err(error_message),
                        _ => (),
                    }
                }

                // Otherwise, return a generic API error
                APIError::new_err(error_message)
            }
            Error::LocalAgent(e) => convert_to_default_error(&e),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
