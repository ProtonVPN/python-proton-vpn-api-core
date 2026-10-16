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
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from proton.vpn.backend.networkmanager.protocol.protun import (
    protun as protun_module
)
from proton.vpn.backend.networkmanager.protocol.protun.protun import (
    Protun, ProtunUDP, ProtunTCP, ProtunTLS, ProtunSmart, generate_capture_path,
)
from proton.vpn.backend.networkmanager.core.networkmanager import LinuxNetworkManager
from proton.vpn.core.settings.packet_capture import PacketCaptureMode


# ─── generate_capture_path ────────────────────────────────────────────────────

def test_generate_capture_path():
    result = generate_capture_path("/tmp", datetime(2026, 4, 30, 14, 30, 45))
    assert result == Path("/tmp/proton_vpn__2026_04_30__14_30_45.pcap")

# ─── Protun class methods ─────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_is_valid():
    original = Protun._is_valid
    yield
    Protun._is_valid = original


@pytest.mark.parametrize("cls", [Protun, ProtunUDP, ProtunTCP, ProtunTLS, ProtunSmart])
def test_supports_packet_capture(cls):
    assert cls.supports_packet_capture(MagicMock()) is True


def test_supports_packet_capture_returns_false_when_module_unavailable():
    assert Protun.supports_packet_capture(None) is False


def test_validate_returns_false_when_not_valid():
    Protun._is_valid = False
    assert Protun.validate() is False


def test_validate_returns_true_when_valid():
    Protun._is_valid = True
    assert Protun.validate() is True


@pytest.mark.parametrize(
    "nm_compatible,nm_supported,sandboxed,plugin_exists,expected",
    [
        (True,  True,  False, True,  True),
        (False, True,  False, True,  False),  # NM version not compatible
        (True,  False, False, True,  False),  # NM too old
        (True,  True,  True,  True,  False),  # snap / flatpak
        (True,  True,  False, False, False),  # plugin not installed
    ],
)
def test_check_is_valid(
    nm_compatible, nm_supported, sandboxed, plugin_exists, expected
):
    nm = MagicMock() if nm_supported else MagicMock(spec=[])
    nm_validate = patch.object(
        LinuxNetworkManager, "validate", return_value=nm_compatible
    )
    sandbox = patch.object(
        protun_module, "in_a_sandbox", return_value=sandboxed
    )
    plugin = patch.object(Protun, "_plugin_exists", return_value=plugin_exists)
    with nm_validate, patch.object(protun_module, "NM", nm), sandbox, plugin:
        assert Protun._check_is_valid() is expected


def test_validate_only_checks_requirements_once():
    Protun._is_valid = None
    with patch.object(Protun, "_check_is_valid", return_value=True) as check:
        assert Protun.validate() is True
        assert Protun.validate() is True

    check.assert_called_once()


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _make_instance(mode, directory_path="/tmp", max_bytes=512 * 1024 * 1024, protun=None):
    """Build a bare ProtunUDP instance without invoking __init__."""
    instance = object.__new__(ProtunUDP)
    instance._protun_client = None
    instance._protun = protun

    packet_capture = MagicMock()
    packet_capture.mode = mode
    packet_capture.directory_path = directory_path
    packet_capture.max_bytes = max_bytes

    settings = MagicMock()
    settings.packet_capture = packet_capture
    instance._settings = settings
    return instance


# ─── start_packet_capture ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_start_packet_capture_uses_overwrite_mode():
    mock_protun = MagicMock()
    mock_protun.ConnectionManager.new = AsyncMock(return_value=MagicMock(run=AsyncMock()))
    instance = _make_instance(PacketCaptureMode.OVERWRITE, protun=mock_protun)

    await instance.start_packet_capture()

    _, kwargs = mock_protun.PcapFileInfo.from_path.call_args
    assert kwargs["mode"] is mock_protun.FileWriteMode.Overwrite


@pytest.mark.asyncio
async def test_start_packet_capture_uses_append_mode():
    mock_protun = MagicMock()
    mock_protun.ConnectionManager.new = AsyncMock(return_value=MagicMock(run=AsyncMock()))
    instance = _make_instance(PacketCaptureMode.APPEND, protun=mock_protun)

    await instance.start_packet_capture()

    _, kwargs = mock_protun.PcapFileInfo.from_path.call_args
    assert kwargs["mode"] is mock_protun.FileWriteMode.Append


@pytest.mark.asyncio
async def test_start_packet_capture_passes_max_bytes():
    mock_protun = MagicMock()
    mock_protun.ConnectionManager.new = AsyncMock(return_value=MagicMock(run=AsyncMock()))
    max_bytes = 1024 * 1024 * 100
    instance = _make_instance(PacketCaptureMode.OVERWRITE, max_bytes=max_bytes, protun=mock_protun)

    await instance.start_packet_capture()

    _, kwargs = mock_protun.PcapStart.call_args
    assert kwargs["max_bytes"] == max_bytes


@pytest.mark.asyncio
async def test_start_packet_capture_sends_pcap_start_command():
    mock_protun = MagicMock()
    mock_client = MagicMock(run=AsyncMock())
    mock_protun.ConnectionManager.new = AsyncMock(return_value=mock_client)
    instance = _make_instance(PacketCaptureMode.OVERWRITE, protun=mock_protun)

    await instance.start_packet_capture()

    mock_client.run.assert_called_once_with(
        mock_protun.Command.PcapStart.return_value
    )


# ─── stop_packet_capture ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_stop_packet_capture_sends_pcap_stop_command():
    mock_protun = MagicMock()
    mock_client = MagicMock(run=AsyncMock())
    mock_protun.ConnectionManager.new = AsyncMock(return_value=mock_client)
    instance = object.__new__(ProtunUDP)
    instance._protun_client = None
    instance._protun = mock_protun

    await instance.stop_packet_capture()

    mock_protun.PcapStop.assert_called_once_with()
    mock_client.run.assert_called_once_with(
        mock_protun.Command.PcapStop.return_value
    )
