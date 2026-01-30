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
//! NetworkManager VPN plugin binary.
//!
//! Entry point for the protun service that integrates ProtonVPN with
//! NetworkManager via D-Bus.
//!
//! This just delegates to the services::protun::run function.

#[cfg(feature = "protun")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    python_proton_vpn_linux::services::protun::run().await // TODO remove python_ prefix once local agent is merged in
}

#[cfg(not(feature = "protun"))]
fn main() {
    eprintln!("This binary requires the 'protun' feature to be enabled.");
    eprintln!("Build with: cargo build --features protun --bin protun");
    std::process::exit(1);
}
