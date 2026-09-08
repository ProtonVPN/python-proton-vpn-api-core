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
use pyo3::types::PyModule;

pub fn register(py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::Bound<'_, PyModule>> {
    use pyo3::types::PyModuleMethods as _;

    let telemetry = PyModule::new(py, "telemetry")?;
    telemetry.add_class::<super::ConnectionOutcome>()?;
    telemetry.add_class::<super::ConnectionEventBuilder>()?;
    telemetry.add_class::<super::EventInfo>()?;
    telemetry.add_class::<super::TelemetryEvents>()?;
    Ok(telemetry)
}
