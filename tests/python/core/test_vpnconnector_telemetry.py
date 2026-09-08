"""
Tests for `VPNConnectorTelemetry`.


Copyright (c) 2026 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton VPN is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
from unittest.mock import Mock

import pytest

from proton.vpn.connection import states
from proton.vpn.core.vpnconnector_telemetry import VPNConnectorTelemetry
from proton.vpn.platform.telemetry import TelemetryEvents  # pylint: disable=no-name-in-module, import-error


def _make_reporter(*, telemetry, user_tier=1):
    return VPNConnectorTelemetry(
        session_holder=Mock(user_tier=user_tier),
        telemetry=telemetry,
    )


def _state_with_connection(state_cls, protocol):
    return state_cls(
        context=states.StateContext(connection=Mock(protocol=protocol))
    )


def _enabled_telemetry():
    tel = TelemetryEvents(10)
    tel.enable(True)
    return tel


def _run_attempt(reporter, terminal_state_cls, protocol="protun-udp"):
    """Simulate a Connecting → terminal transition."""
    reporter.report_telemetry(_state_with_connection(states.Connecting, protocol))
    reporter.report_telemetry(_state_with_connection(terminal_state_cls, protocol))


@pytest.mark.parametrize("state_cls, expected_outcome", [
    (states.Connected, "success"),
    (states.Error, "failure"),
    (states.Disconnected, "aborted"),
])
def test_report_telemetry_maps_terminal_state_to_outcome(state_cls, expected_outcome):
    tel = _enabled_telemetry()
    reporter = _make_reporter(telemetry=tel)

    _run_attempt(reporter, state_cls)

    out = tel.flush_events()
    assert len(out) == 1
    assert out[0]["Dimensions"]["outcome"] == expected_outcome


def test_terminal_without_prior_connecting_is_dropped():
    tel = _enabled_telemetry()
    reporter = _make_reporter(telemetry=tel)

    reporter.report_telemetry(_state_with_connection(states.Connected, "protun-udp"))

    assert tel.flush_events() == []


def test_post_connected_disconnect_is_dropped():
    """Connected already submits and clears; the trailing Disconnected has no pending builder."""
    tel = _enabled_telemetry()
    reporter = _make_reporter(telemetry=tel)

    _run_attempt(reporter, states.Connected)
    reporter.report_telemetry(_state_with_connection(states.Disconnected, "protun-udp"))

    out = tel.flush_events()
    assert len(out) == 1
    assert out[0]["Dimensions"]["outcome"] == "success"


def test_second_connecting_supersedes_first():
    tel = _enabled_telemetry()
    reporter = _make_reporter(telemetry=tel)

    reporter.report_telemetry(_state_with_connection(states.Connecting, "protun-udp"))
    reporter.report_telemetry(_state_with_connection(states.Connecting, "wireguard"))
    reporter.report_telemetry(_state_with_connection(states.Connected, "wireguard"))

    out = tel.flush_events()
    assert len(out) == 1
    assert out[0]["Dimensions"]["protocol"] == "wireguard_udp"


def test_connecting_without_connection_is_ignored():
    tel = _enabled_telemetry()
    reporter = _make_reporter(telemetry=tel)

    # Default StateContext -> connection is None.
    reporter.report_telemetry(states.Connecting())
    reporter.report_telemetry(_state_with_connection(states.Connected, "protun-udp"))

    # The Connecting was dropped, so the Connected has no pending builder either.
    assert tel.flush_events() == []


def test_produces_nothing_when_telemetry_disabled():
    tel = TelemetryEvents(10)
    # Never enabled -> submit no-ops.
    reporter = _make_reporter(telemetry=tel)

    _run_attempt(reporter, states.Connected)

    assert tel.flush_events() == []


@pytest.mark.parametrize("python_protocol, wire_protocol, is_smart", [
    ("protun-udp", "protun_udp", False),
    ("protun-tcp", "protun_tcp", False),
    ("protun-tls", "protun_tls", False),
    ("wireguard", "wireguard_udp", False),
    ("wireguard-tcp", "wireguard_tcp", False),
    ("wireguard-tls", "wireguard_tls", False),
    ("openvpn-udp", "openvpn_udp", False),
    ("openvpn-tcp", "openvpn_tcp", False),
    ("protun-smart", "protun", True),
])
def test_report_telemetry_maps_protocol_dimension(
    python_protocol, wire_protocol, is_smart
):
    tel = _enabled_telemetry()
    reporter = _make_reporter(telemetry=tel)

    _run_attempt(reporter, states.Connected, protocol=python_protocol)

    dims = tel.flush_events()[0]["Dimensions"]
    assert dims["protocol"] == wire_protocol
    assert dims["is_smart_protocol"] == ("true" if is_smart else "false")


@pytest.mark.parametrize("user_tier, wire_tier", [
    (None, "unknown"),
    (0, "free"),
    (1, "unknown"),
    (2, "paid"),
    (3, "internal"),
])
def test_report_telemetry_maps_user_tier_dimension(user_tier, wire_tier):
    tel = _enabled_telemetry()
    reporter = _make_reporter(telemetry=tel, user_tier=user_tier)

    _run_attempt(reporter, states.Connected)

    assert tel.flush_events()[0]["Dimensions"]["user_tier"] == wire_tier
