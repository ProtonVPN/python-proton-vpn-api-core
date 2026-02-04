// -----------------------------------------------------------------------------
// Copyright (c) 2026 Proton AG
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
//! Python bindings for core module.
//!

use pyo3::prelude::*;
use pyo3::types::PyModule;

pub fn register(
    py: Python,
    parent: &Bound<'_, PyModule>,
) -> pyo3::PyResult<()> {
    use super::ProtonVpnLinuxError;
    let core = PyModule::new(py, "core")?;
    core.add_class::<super::ServerStatus>()?;
    core.add(
        stringify!(ProtonVpnLinuxError),
        core.py().get_type::<ProtonVpnLinuxError>(),
    )?;
    parent.add_submodule(&core)?;
    Ok(())
}
