// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use crate::{ErrorMessage, ExpiredCertificateError, LocalAgentError};
use local_agent_rs as la;
use pyo3::exceptions::PyTimeoutError;
use pyo3::{PyErr, PyResult};
use std::fmt::Write;
use std::io::ErrorKind;

/// Converts a la::Result to a native python object.
///
/// py03 will automatically convert errors in the PyResult object to
/// python exceptions.
///
fn convert_error_message_string<T: std::fmt::Debug>(error: T) -> String {
    let mut error_message = String::new();
    writeln!(&mut error_message, "{:?}", error)
        .expect("Unable to write to error string");

    error_message
}

fn convert_to_default_error<T: std::fmt::Debug>(error: T) -> PyErr {
    LocalAgentError::new_err(convert_error_message_string(error))
}

pub fn result_to_py<T>(e: la::Result<T>) -> PyResult<T> {
    match e {
        Ok(value) => Ok(value),
        Err(la::Error::Tokio(e)) => match e.kind() {
            ErrorKind::InvalidData => Err(ExpiredCertificateError::new_err(
                convert_error_message_string(e),
            )),
            ErrorKind::TimedOut => {
                Err(PyTimeoutError::new_err(convert_error_message_string(e)))
            }
            _ => Err(convert_to_default_error(e)),
        },
        Err(la::Error::TokioElapsed(e)) => {
            Err(PyTimeoutError::new_err(convert_error_message_string(e)))
        }
        Err(la::Error::GetStatusError(e)) => {
            Err(ErrorMessage::new_err(convert_error_message_string(e)))
        }
        Err(e) => Err(convert_to_default_error(e)),
    }
}
