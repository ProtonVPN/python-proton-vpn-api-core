// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use pyo3::prelude::*;
// -----------------------------------------------------------------------------
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    VpnLib(#[from] proton_vpn_lib_rs::Error),
    #[error("{0}")]
    Pythonize(#[from] pythonize::PythonizeError),
    #[error("{0}")]
    PyErr(#[from] pyo3::PyErr),
}

pyo3::create_exception!(lib, ProtonVpnLibError, pyo3::exceptions::PyException);

impl std::convert::From<Error> for PyErr {
    fn from(err: Error) -> PyErr {
        match err {
            Error::VpnLib(e) => ProtonVpnLibError::new_err(format!("VpnLib {e}")),
            Error::Pythonize(e) => ProtonVpnLibError::new_err(format!("Pythonize{e}")),
            Error::PyErr(e) => ProtonVpnLibError::new_err(format!("PyErr {e}")),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
