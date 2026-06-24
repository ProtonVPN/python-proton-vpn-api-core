// -----------------------------------------------------------------------------
// Copyright (c) 2025 Proton AG
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

use super::super::error::Error;

use pyo3::prelude::*;
use pyo3::types::PyModule;

#[cfg(feature = "python")]
pyo3::create_exception!(
    lib,
    ProtonVpnError,
    pyo3::exceptions::PyException
);

#[cfg(feature = "python")]
impl std::convert::From<Error> for pyo3::PyErr {
    fn from(err: Error) -> pyo3::PyErr {
        ProtonVpnError::new_err(format!("{:?}", &err))
    }
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()>  {
    m.add(stringify!(ProtonVpnError), m.py().get_type::<ProtonVpnError>())?;

    Ok(())
}

