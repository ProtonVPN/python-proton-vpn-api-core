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
from unittest.mock import AsyncMock, MagicMock

import pytest

from proton.vpn.backend.networkmanager.protocol.protun.protun import (
    Protun, ProtunUDP, generate_capture_path,
)
from proton.vpn.core.settings.packet_capture import PacketCaptureMode


# ─── generate_capture_path ────────────────────────────────────────────────────

def test_generate_capture_path():
    result = generate_capture_path("/tmp", datetime(2026, 4, 30, 14, 30, 45))
    assert result == Path("/tmp/proton_vpn__2026_04_30__14_30_45.pcap")

# ─── Protun class methods ─────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_plugin_exists():
    original = Protun.plugin_exists
    yield
    Protun.plugin_exists = original


def test_supports_packet_capture_():
    assert Protun.supports_packet_capture(MagicMock()) is False


def test_udp_supports_packet_capture():
    assert ProtunUDP.supports_packet_capture(MagicMock()) is True


def test_supports_packet_capture_returns_false_when_module_unavailable():
    assert Protun.supports_packet_capture(None) is False


def test_validate_returns_false_when_plugin_does_not_exist():
    Protun.plugin_exists = False
    assert Protun.validate() is False


def test_validate_returns_true_when_plugin_exists_and_module_available():
    Protun.plugin_exists = True
    assert Protun.validate() is True


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
