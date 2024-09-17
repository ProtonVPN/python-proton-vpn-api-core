// -----------------------------------------------------------------------------
// Copyright (c) 2024 Proton AG
// -----------------------------------------------------------------------------
use pyo3::create_exception;
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
    ErrorMessage,
    LocalAgentError,
    "Raised when an error message is read from socket."
);
