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
//! Wire format types for the `data/v1/stats/multiple` telemetry endpoint.
//!
//! These types define the JSON contract with the backend; the in-memory
//! queue in [`super`] embeds them but is otherwise agnostic to their shape.

use std::time::Instant;

use serde::{Serialize, Serializer};

const MEASUREMENT_GROUP: &str = "vpn.any.connection";
const EVENT_NAME: &str = "vpn_connection";

/// Terminal outcome of a connection attempt.
///
/// Serializes to the lowercase wire string (`success`, `failure`, `aborted`).
#[cfg_attr(feature = "python", pyo3::pyclass(eq, eq_int))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionOutcome {
    /// Reached `Connected`.
    Success,
    /// Reached `Error`.
    Failure,
    /// Reached `Disconnected` before `Connected`.
    Aborted,
}

/// `Dimensions` object on the wire for a `vpn_connection` event.
///
/// Not exposed to Python — Python callers construct events via
/// [`ConnectionEventBuilder`] and pass the resulting [`EventInfo`] to
/// [`super::TelemetryEvents::submit`].
#[derive(Clone, Debug, Serialize)]
pub struct ConnectionEvent {
    pub outcome: ConnectionOutcome,
    pub protocol: String,
    pub user_tier: String,
    #[serde(serialize_with = "serialize_bool_as_string")]
    pub is_smart_protocol: bool,
}

fn serialize_bool_as_string<S: Serializer>(value: &bool, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(if *value { "true" } else { "false" })
}

/// In-flight connection attempt: captures start time and the immutable
/// dimensions known at `Connecting`. Call [`Self::build`] with the terminal
/// outcome to snap the timer and produce a submittable [`EventInfo`].
#[cfg_attr(feature = "python", pyo3::pyclass)]
pub struct ConnectionEventBuilder {
    start_time: Instant,
    protocol: String,
    user_tier: String,
    is_smart_protocol: bool,
}

impl ConnectionEventBuilder {
    pub fn new(protocol: String, user_tier: String, is_smart_protocol: bool) -> Self {
        Self {
            start_time: Instant::now(),
            protocol,
            user_tier,
            is_smart_protocol,
        }
    }
}

#[cfg_attr(feature = "python", pyo3::pymethods)]
impl ConnectionEventBuilder {
    /// Snap the timer and materialize the event with the given outcome.
    pub fn build(&self, outcome: ConnectionOutcome) -> EventInfo {
        let time_to_connection = self.start_time.elapsed().as_millis() as f64;
        EventInfo::new(
            ConnectionEvent {
                outcome,
                protocol: self.protocol.clone(),
                user_tier: self.user_tier.clone(),
                is_smart_protocol: self.is_smart_protocol,
            },
            time_to_connection,
        )
    }
}

/// One entry in the `EventInfo[]` array POSTed to `data/v1/stats/multiple`.
#[cfg_attr(feature = "python", pyo3::pyclass)]
#[derive(Clone, Debug, Serialize)]
pub struct EventInfo {
    #[serde(rename = "MeasurementGroup")]
    measurement_group: &'static str,
    #[serde(rename = "Event")]
    event: &'static str,
    #[serde(rename = "Values")]
    pub(crate) values: EventValues,
    #[serde(rename = "Dimensions")]
    pub(crate) dimensions: ConnectionEvent,
}

impl EventInfo {
    /// Build a `vpn_connection` event with the given dimensions and duration.
    pub fn new(dimensions: ConnectionEvent, time_to_connection: f64) -> Self {
        Self {
            measurement_group: MEASUREMENT_GROUP,
            event: EVENT_NAME,
            values: EventValues { time_to_connection },
            dimensions,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct EventValues {
    pub(crate) time_to_connection: f64,
}
