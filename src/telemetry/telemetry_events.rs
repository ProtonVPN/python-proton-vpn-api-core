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
// -----------------------------------------------------------------------------
//! Bounded in-memory queue of `vpn_connection` telemetry events.

#[cfg(feature = "python")]
use pyo3::prelude::*;

use super::wire::{ConnectionEventBuilder, EventInfo};

/// Bounded telemetry event queue.
///
/// Disabled at construction. While disabled, [`Self::submit`] is a no-op.
/// [`Self::connect_event`] is always a pure factory — it captures a start
/// time and hands the caller a [`ConnectionEventBuilder`] regardless of
/// the enabled state. Never raises across an FFI boundary — all failures
/// are silent.
#[cfg_attr(feature = "python", pyo3::pyclass)]
pub struct TelemetryEvents {
    enabled: bool,
    queue_cap: usize,
    queue: Vec<EventInfo>,
}

impl TelemetryEvents {
    /// Create a disabled queue with the given capacity.
    pub fn new(queue_cap: usize) -> Self {
        Self {
            enabled: false,
            queue_cap,
            queue: Vec::new(),
        }
    }

    /// Drain the queue.
    ///
    /// The Python-facing view is [`Self::py_flush_events`], which
    /// pythonizes each entry into a native dict.
    pub fn flush_events(&mut self) -> Vec<EventInfo> {
        std::mem::take(&mut self.queue)
    }
}

#[cfg_attr(feature = "python", pyo3::pymethods)]
impl TelemetryEvents {
    #[cfg(feature = "python")]
    #[new]
    pub fn py_new(queue_cap: usize) -> Self {
        Self::new(queue_cap)
    }

    /// Flip the enable gate. Disabling does not drain the queue.
    pub fn enable(&mut self, enable: bool) {
        self.enabled = enable;
    }

    /// Start a new connection attempt.
    ///
    /// Returns a builder that captures the start time and the dimensions
    /// known at `Connecting`. Call [`ConnectionEventBuilder::build`] with
    /// the terminal outcome, then pass the resulting [`EventInfo`] to
    /// [`Self::submit`].
    pub fn connect_event(
        &self,
        protocol: String,
        user_tier: String,
        is_smart_protocol: bool,
    ) -> ConnectionEventBuilder {
        ConnectionEventBuilder::new(protocol, user_tier, is_smart_protocol)
    }

    /// Enqueue a fully-built event.
    ///
    /// Silently drops when disabled or when the queue is at capacity.
    pub fn submit(&mut self, event: EventInfo) {
        if !self.enabled {
            return;
        }
        if self.queue.len() >= self.queue_cap {
            return;
        }
        self.queue.push(event);
    }

    /// Drain the queue as a list of native Python dicts, ready to be POSTed
    /// via `jsondata=`.
    #[cfg(feature = "python")]
    #[pyo3(name = "flush_events")]
    pub fn py_flush_events<'py>(
        &mut self,
        py: Python<'py>,
    ) -> PyResult<Bound<'py, PyAny>> {
        Ok(pythonize::pythonize(py, &self.flush_events())?)
    }
}

#[cfg(test)]
mod tests {
    use super::super::wire::ConnectionOutcome;
    use super::*;

    fn attempt(t: &TelemetryEvents) -> ConnectionEventBuilder {
        t.connect_event("protun_udp".into(), "paid".into(), false)
    }

    #[test]
    fn disabled_by_default_records_nothing() {
        let mut t = TelemetryEvents::new(10);
        let event = attempt(&t).build(ConnectionOutcome::Success);
        t.submit(event);
        assert!(t.flush_events().is_empty());
    }

    #[test]
    fn disabling_after_start_suppresses_submit() {
        let mut t = TelemetryEvents::new(10);
        t.enable(true);
        let builder = attempt(&t);
        t.enable(false);
        t.submit(builder.build(ConnectionOutcome::Success));
        assert!(t.flush_events().is_empty());
    }

    #[test]
    fn paired_attempt_submit_produces_one_event() {
        let mut t = TelemetryEvents::new(10);
        t.enable(true);
        t.submit(attempt(&t).build(ConnectionOutcome::Success));
        let events = t.flush_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].dimensions.outcome, ConnectionOutcome::Success);
        assert_eq!(events[0].dimensions.protocol, "protun_udp");
        assert_eq!(events[0].dimensions.user_tier, "paid");
        assert!(!events[0].dimensions.is_smart_protocol);
    }

    #[test]
    fn each_builder_owns_its_own_timer() {
        let mut t = TelemetryEvents::new(10);
        t.enable(true);
        let first = attempt(&t);
        std::thread::sleep(std::time::Duration::from_millis(20));
        let second = attempt(&t);
        // Both are independent; submitting the second measures ~0ms while
        // the first would measure ~20ms.
        t.submit(second.build(ConnectionOutcome::Success));
        let events = t.flush_events();
        assert_eq!(events.len(), 1);
        assert!(events[0].values.time_to_connection < 20.0);
        // The first builder was never submitted; nothing to observe.
        drop(first);
    }

    #[test]
    fn queue_cap_drops_further_events() {
        let mut t = TelemetryEvents::new(2);
        t.enable(true);
        for _ in 0..5 {
            t.submit(attempt(&t).build(ConnectionOutcome::Success));
        }
        assert_eq!(t.flush_events().len(), 2);
    }

    #[test]
    fn flush_when_empty_returns_empty() {
        let mut t = TelemetryEvents::new(10);
        assert!(t.flush_events().is_empty());
        t.enable(true);
        assert!(t.flush_events().is_empty());
    }

    #[test]
    fn flush_drains_the_queue() {
        let mut t = TelemetryEvents::new(10);
        t.enable(true);
        t.submit(attempt(&t).build(ConnectionOutcome::Success));
        assert_eq!(t.flush_events().len(), 1);
        assert!(t.flush_events().is_empty());
    }

    #[test]
    fn event_serializes_to_expected_wire_shape() {
        let mut t = TelemetryEvents::new(10);
        t.enable(true);
        let builder =
            t.connect_event("wireguard_udp".into(), "free".into(), true);
        t.submit(builder.build(ConnectionOutcome::Failure));
        let json = serde_json::to_value(&t.flush_events()[0]).unwrap();
        assert_eq!(json["MeasurementGroup"], "vpn.any.connection");
        assert_eq!(json["Event"], "vpn_connection");
        assert_eq!(json["Dimensions"]["outcome"], "failure");
        assert_eq!(json["Dimensions"]["protocol"], "wireguard_udp");
        assert_eq!(json["Dimensions"]["user_tier"], "free");
        assert_eq!(json["Dimensions"]["is_smart_protocol"], "true");
        assert!(json["Values"]["time_to_connection"].is_number());
    }
}
