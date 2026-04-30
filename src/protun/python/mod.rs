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
use pyo3::types::PyModule;

pub fn register(py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::Bound<'_, PyModule>> {
    use pyo3::types::PyModuleMethods as _;

    let protun = PyModule::new(py, "protun")?;
    protun.add_class::<super::core::ConnectionManager>()?;
    protun.add_class::<super::core::Command>()?;
    protun.add_class::<super::core::PcapStop>()?;
    protun.add_class::<super::core::PcapStart>()?;
    protun.add_class::<super::core::PcapFileInfo>()?;
    protun.add_class::<super::core::FileWriteMode>()?;
    Ok(protun)
}
