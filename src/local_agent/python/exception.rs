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
    NotYetValidCertificateError,
    LocalAgentError,
    "Raised when the passed certificate is not yet valid during read from socket."
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
    m.add("LocalAgentError", m.py().get_type::<LocalAgentError>())?;
    m.add(
        "ExpiredCertificateError",
        m.py().get_type::<ExpiredCertificateError>(),
    )?;
    m.add(
        "NotYetValidCertificateError",
        m.py().get_type::<NotYetValidCertificateError>(),
    )?;
    m.add("APIError", m.py().get_type::<APIError>())?;
    m.add("SyntaxAPIError", m.py().get_type::<SyntaxAPIError>())?;
    m.add("PolicyAPIError", m.py().get_type::<PolicyAPIError>())?;

    Ok(())
}
