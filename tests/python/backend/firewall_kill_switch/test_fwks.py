"""
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
from unittest.mock import AsyncMock, Mock, call

import pytest

from proton.vpn.backend.firewall_kill_switch import FirewallKillSwitch
from proton.vpn.backend.firewall_kill_switch.fwks import FEATURE_FLAG

SUPPORTED_PARAMS = {"protocol": "wireguard"}


@pytest.fixture
def vpn_server():
    vpn_server_mock = Mock()
    vpn_server_mock.server_ip = "1.1.1.1"

    return vpn_server_mock


def fake_client(service_available: bool):
    """Returns a stand-in client that answers without touching D-Bus."""
    class FakeDBusClient:
        @staticmethod
        def is_service_available():
            return service_available

    return FakeDBusClient


@pytest.mark.asyncio
async def test_enable_without_vpn_server_does_not_send_a_server_ip():
    dbus_client = AsyncMock()

    await FirewallKillSwitch(dbus_client).enable()

    assert dbus_client.method_calls == [call.enable(server_ip=None)]


@pytest.mark.asyncio
async def test_enable_with_vpn_server_sends_its_ip(vpn_server):
    dbus_client = AsyncMock()

    await FirewallKillSwitch(dbus_client).enable(vpn_server)

    assert dbus_client.method_calls == [call.enable(server_ip="1.1.1.1")]


@pytest.mark.asyncio
async def test_enable_in_permanent_mode_raises_without_applying_anything():
    dbus_client = AsyncMock()

    with pytest.raises(NotImplementedError):
        await FirewallKillSwitch(dbus_client).enable(permanent=True)

    # It has to refuse rather than quietly fall back to a non-permanent kill
    # switch, which would leave the user less protected than they asked for.
    assert dbus_client.method_calls == []


@pytest.mark.asyncio
async def test_disable_removes_the_rules():
    dbus_client = AsyncMock()

    await FirewallKillSwitch(dbus_client).disable()

    assert dbus_client.method_calls == [call.disable()]


@pytest.mark.parametrize(
    "validate_params",
    [None, {}, {"protocol": None}, {"protocol": "openvpn"}]
)
def test_validate_rejects_unsupported_protocols(validate_params, monkeypatch):
    monkeypatch.setenv(FEATURE_FLAG, "1")

    assert FirewallKillSwitch._validate(
        validate_params, dbus_client=fake_client(True)
    ) is False


def test_validate_rejects_when_the_feature_flag_is_not_set(monkeypatch):
    monkeypatch.delenv(FEATURE_FLAG, raising=False)

    assert FirewallKillSwitch._validate(
        SUPPORTED_PARAMS, dbus_client=fake_client(True)
    ) is False


def test_validate_does_not_probe_the_bus_when_the_flag_is_not_set(monkeypatch):
    # Probing connects to D-Bus on a worker thread and can block for seconds,
    # so the cheap checks have to come first.
    monkeypatch.delenv(FEATURE_FLAG, raising=False)

    class RecordingDBusClient:
        """Records whether _validate got as far as probing the bus."""

        called = False

        @classmethod
        def is_service_available(cls):
            cls.called = True
            return True

    FirewallKillSwitch._validate(
        SUPPORTED_PARAMS, dbus_client=RecordingDBusClient
    )

    assert not RecordingDBusClient.called


def test_validate_rejects_when_the_service_does_not_answer(monkeypatch):
    monkeypatch.setenv(FEATURE_FLAG, "1")

    assert FirewallKillSwitch._validate(
        SUPPORTED_PARAMS, dbus_client=fake_client(False)
    ) is False


@pytest.mark.parametrize("protocol", ["wireguard", "protun-udp", "protun-tcp"])
def test_validate_accepts_when_flag_is_set_and_service_answers(
        protocol, monkeypatch
):
    monkeypatch.setenv(FEATURE_FLAG, "1")

    assert FirewallKillSwitch._validate(
        {"protocol": protocol}, dbus_client=fake_client(True)
    ) is True
