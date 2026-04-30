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
use pyo3::prelude::*;
use pyo3::types::PyModule;

/// Extension trait for PyModule that adds submodules and registers them for import.
pub trait SubModule {
    /// Add a submodule and register it in sys.modules so it can be imported.
    ///
    /// The `full_name` should be the complete dotted path, e.g., "mymodule.submodule".
    fn add_import_submodule(&self, py: Python<'_>, submodule: &Bound<'_, PyModule>, full_name: &str) -> PyResult<()>;
}

impl SubModule for Bound<'_, PyModule> {
    fn add_import_submodule(&self, py: Python<'_>, submodule: &Bound<'_, PyModule>, full_name: &str) -> PyResult<()> {
        // Add as attribute for parent.submodule access
        self.add_submodule(submodule)?;
        
        // Register in sys.modules for import statements
        py.import("sys")?
            .getattr("modules")?
            .set_item(full_name, submodule)?;
        
        Ok(())
    }
}
