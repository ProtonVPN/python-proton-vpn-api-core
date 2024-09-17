// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use pyo3::create_exception;
use pyo3::prelude::*;
// -----------------------------------------------------------------------------

create_exception!(
    local_agent,
    LocalAgentError,
    pyo3::exceptions::PyException,
    "General exception."
);

create_exception!(
    local_agent,
    ExpiredCertificateError,
    LocalAgentError,
    "Raised when the passed certificate is expired during read from socket."
);

create_exception!(
    local_agent,
    APIError,
    LocalAgentError,
    "Raised when an error message is read from socket."
);

create_exception!(
    local_agent,
    SyntaxAPIError,
    APIError,
    "Raised when there is a syntax error using the api."
);

create_exception!(
    local_agent,
    PolicyAPIError,
    APIError,
    "Raised when there is a policy error using the api."
);

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add(
        "LocalAgentError",
        m.py().get_type_bound::<LocalAgentError>(),
    )?;
    m.add(
        "ExpiredCertificateError",
        m.py().get_type_bound::<ExpiredCertificateError>(),
    )?;
    m.add("APIError", m.py().get_type_bound::<APIError>())?;
    m.add("SyntaxAPIError", m.py().get_type_bound::<SyntaxAPIError>())?;
    m.add("PolicyAPIError", m.py().get_type_bound::<PolicyAPIError>())?;

    Ok(())
}
