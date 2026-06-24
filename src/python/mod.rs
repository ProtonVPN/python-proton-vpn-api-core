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

mod await_py;
mod exceptions;
mod logger;
mod submodule;

use pyo3::prelude::*;

pub use submodule::SubModule;
pub(crate) use await_py::{future, await_py};

#[pyo3::pymodule]
#[pyo3(name = "platform")]
fn py_init_platform(
    py: pyo3::prelude::Python,
    m: &pyo3::prelude::Bound<'_, pyo3::prelude::PyModule>,
) -> pyo3::PyResult<()> {
    use submodule::SubModule as _;

    exceptions::register(m)?;

    m.add_function(wrap_pyfunction!(logger::init_logger, m)?)?;

    #[cfg(feature = "core")]
    m.add_import_submodule(py, &super::core::python::register(py)?, "proton.vpn.platform.core")?;

    #[cfg(feature = "local_agent")]
    m.add_import_submodule(py, &super::local_agent::python::register(py)?, "proton.vpn.platform.local_agent")?;

    #[cfg(feature = "protun")]
    m.add_import_submodule(py, &super::protun::python::register(py)?, "proton.vpn.platform.protun")?;

    Ok(())
}
