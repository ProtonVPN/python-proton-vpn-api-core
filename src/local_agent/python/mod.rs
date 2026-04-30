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
use super::{AgentConnector, AgentConnection, AgentFeatures, ConnectionDetails, Listener, Reason,
            ReasonCode, State, Status};

mod exception;

pub use exception::*;

use pyo3::types::PyModule;

pub fn register(py: pyo3::Python<'_>) -> pyo3::PyResult<pyo3::Bound<'_, PyModule>> {
    use pyo3::types::PyModuleMethods as _;

    let local_agent = PyModule::new(py, "local_agent")?;

    // Register the exceptions
    exception::register(&local_agent)?;

    // Add the AgentConnection and AgentConnector classes to the module.
    local_agent.add_class::<AgentConnector>()?;
    local_agent.add_class::<AgentConnection>()?;
    local_agent.add_class::<AgentFeatures>()?;
    local_agent.add_class::<State>()?;
    local_agent.add_class::<ReasonCode>()?;
    local_agent.add_class::<Reason>()?;
    local_agent.add_class::<Status>()?;
    local_agent.add_class::<ConnectionDetails>()?;
    local_agent.add_class::<Listener>()?;
    
    Ok(local_agent)
}