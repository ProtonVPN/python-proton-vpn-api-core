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
//! Telemetry event queue for VPN connection attempts.
//!
//! Records one `vpn_connection` event per completed attempt, batched in a
//! bounded in-memory queue and drained by the Python publisher.

mod telemetry_events;
mod wire;

#[cfg(feature = "python")]
pub(crate) mod python;

pub use telemetry_events::TelemetryEvents;
pub use wire::{ConnectionEvent, ConnectionEventBuilder, ConnectionOutcome, EventInfo};
