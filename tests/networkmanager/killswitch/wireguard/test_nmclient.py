"""
Copyright (c) 2023 Proton AG

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
from concurrent.futures import Future
from unittest.mock import Mock, patch

import pytest

from proton.vpn.backend.networkmanager.killswitch.wireguard.nmclient import NMClient

INTERFACE_NAME = "pvpnksintrf0"


def _run_synchronously(function, *args, **kwargs):
    """Drop-in replacement for NMClient._run_on_glib_loop_thread that runs the
    given function synchronously instead of scheduling it on the GLib loop."""
    future = Future()
    future.set_running_or_notify_cancel()
    try:
        future.set_result(function(*args, **kwargs))
    except BaseException as exc:  # pylint: disable=broad-except
        future.set_exception(exc)
    return future


@pytest.fixture
def nm_client():
    with patch.object(NMClient, "initialize_nm_client_singleton"), \
            patch.object(NMClient, "_run_on_glib_loop_thread", side_effect=_run_synchronously), \
            patch("proton.vpn.backend.networkmanager.killswitch.wireguard.nmclient.GObject"):
        client = NMClient()
        client._nm_client = Mock()
        yield client


def _build_connection():
    connection = Mock()
    connection.get_interface_name.return_value = INTERFACE_NAME
    connection.delete_finish.return_value = True

    # Simulate NetworkManager finishing the deletion synchronously by invoking
    # the callback as soon as delete_async is called.
    def delete_async(cancellable, callback, user_data):  # noqa: ARG001
        callback(connection, Mock(), user_data)

    connection.delete_async.side_effect = delete_async
    return connection


def test_remove_connection_resolves_immediately_when_there_is_no_interface(nm_client):
    """When the connection being removed has no active interface, no
    device-removed signal will ever be emitted, so the removal must be
    considered complete as soon as the connection is deleted."""
    nm_client._nm_client.get_devices.return_value = []  # no devices at all
    connection = _build_connection()

    future = nm_client.remove_connection_async(connection)

    assert future.done()
    assert future.result() is None


def test_remove_connection_waits_for_device_removed_when_interface_is_active(nm_client):
    """When the connection being removed has an active interface, the removal
    is only complete once the corresponding device has actually been removed."""
    device = Mock()
    device.get_iface.return_value = INTERFACE_NAME
    nm_client._nm_client.get_devices.return_value = [device]

    # Capture the handler connected to the "device-removed" signal.
    handlers = {}

    def connect(signal_name, handler):
        handlers[signal_name] = handler
        return 1  # handler id

    nm_client._nm_client.connect.side_effect = connect

    connection = _build_connection()

    future = nm_client.remove_connection_async(connection)

    # The connection was deleted, but the device is still present, so the
    # future must not be resolved until the device is actually removed.
    assert not future.done()

    # Simulate NetworkManager emitting the device-removed signal.
    handlers["device-removed"](nm_client._nm_client, device)

    assert future.done()
    assert future.result() is None
