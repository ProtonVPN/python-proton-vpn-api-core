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
//! ProtonVPN Linux client library.
//!
//! Provides VPN connection management, server load computation, and
//! NetworkManager integration for Linux.

#[cfg(feature = "core")]
pub mod core;
pub mod proton;
pub mod services;

#[cfg(feature = "python")]
#[pyo3::pymodule]
#[pyo3(name = "linux")]
fn py_init_linux(
    py: pyo3::prelude::Python,
    m: &pyo3::prelude::Bound<'_, pyo3::prelude::PyModule>,
) -> pyo3::PyResult<()> {
    env_logger::init();
    #[cfg(feature = "core")]
    core::python::register(py, m)?;
    Ok(())
}
