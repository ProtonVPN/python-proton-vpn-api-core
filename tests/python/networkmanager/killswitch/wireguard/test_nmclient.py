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
import asyncio
from concurrent.futures import Future
from types import SimpleNamespace
from unittest.mock import patch

import gi
import pytest

gi.require_version("NM", "1.0")
from gi.repository import NM  # pylint: disable=wrong-import-position

from proton.vpn.backend.networkmanager.killswitch.wireguard import nmclient


def _profile(uuid="c4c15886-3df0-42e6-8d24-623b449dafbf"):
    connection = NM.SimpleConnection.new()
    settings = NM.SettingConnection.new()
    settings.props.id = "pvpn-killswitch-ipv6"
    settings.props.uuid = uuid
    settings.props.type = "dummy"
    settings.props.interface_name = "ipv6leakintrf0"
    settings.add_permission("user", "test-user", None)
    ip4 = NM.SettingIP4Config.new()
    ip4.props.method = "disabled"
    ip6 = NM.SettingIP6Config.new()
    ip6.props.method = "manual"
    ip6.add_address(NM.IPAddress.new(10, "fdeb:446c:912d:8da::", 64))
    ip6.add_dns("::1")
    ip6.props.dns_priority = -1400
    for setting in (settings, NM.SettingDummy.new(), ip4, ip6):
        connection.add_setting(setting)
    assert connection.verify()
    return connection


class _ActiveConnection:
    def __init__(self, connection, state=NM.ActiveConnectionState.ACTIVATING):
        self.connection = connection
        self.state = state
        self.handlers = {}

    def get_uuid(self):
        return self.connection.get_uuid()

    def get_state(self):
        return self.state

    def connect(self, signal, callback):
        assert signal == "state-changed"
        handler = len(self.handlers) + 1
        self.handlers[handler] = callback
        return handler

    def change_state(self, state):
        self.state = state
        for callback in list(self.handlers.values()):
            callback(self, state, 0)


class _FakeNetworkManager:
    def __init__(self):
        self.profiles = []
        self.active = []
        self.add_calls = []
        self.activate_calls = []
        self.hold_add = False
        self.hold_activate = False
        self.add_reply = None
        self.activate_reply = None
        self.add_error = None
        self.activate_error = None
        self.initial_state = NM.ActiveConnectionState.ACTIVATING
        self.autoconnect_on_add = False
        self.handlers = {}

    def connect(self, signal, callback):
        assert signal == "device-added"
        handler = len(self.handlers) + 1
        self.handlers[handler] = callback
        return handler

    def get_connections(self):
        # NM returns normalized profiles, including defaults absent from a
        # caller's SimpleConnection. Apply that boundary to seeded fixtures.
        for connection in self.profiles:
            connection.normalize()
        return self.profiles

    def get_active_connections(self):
        return self.active

    def add_connection_async(self, **kwargs):
        self.add_calls.append(kwargs)
        connection = NM.SimpleConnection.new_clone(kwargs["connection"])
        connection.normalize()
        if self.add_error is None:
            self.profiles.append(connection)
            if self.autoconnect_on_add:
                self.active.append(_ActiveConnection(
                    connection, self.initial_state
                ))
        self.add_reply = lambda: kwargs["callback"](self, connection, None)
        if not self.hold_add:
            self.add_reply()

    def add_connection_finish(self, result):
        if self.add_error:
            raise self.add_error
        return result

    def activate_connection_async(self, **kwargs):
        self.activate_calls.append(kwargs)
        active = _ActiveConnection(kwargs["connection"], self.initial_state)
        self.active.append(active)
        self.activate_reply = lambda: kwargs["callback"](self, active, None)
        if not self.hold_activate:
            self.activate_reply()

    def activate_connection_finish(self, result):
        if self.activate_error:
            raise self.activate_error
        return result


@pytest.fixture
def client():
    fake_nm = _FakeNetworkManager()
    result = nmclient.NMClient.__new__(nmclient.NMClient)
    result._nm_client = fake_nm

    def dispatch(function, *args, **kwargs):
        future = Future()
        try:
            future.set_result(function(*args, **kwargs))
        except Exception as error:  # pylint: disable=broad-except
            future.set_exception(error)
        return future

    result._run_on_glib_loop_thread = dispatch
    with patch.object(nmclient, "GObject", SimpleNamespace(
        signal_handler_disconnect=lambda obj, handler: obj.handlers.pop(handler)
    )):
        yield result


def test_new_profile_is_explicitly_activated(client):
    future = client.add_connection_async(_profile(), save_to_disk=False)
    fake_nm = client._nm_client

    assert len(fake_nm.add_calls) == 1
    assert fake_nm.add_calls[0]["save_to_disk"] is False
    assert len(fake_nm.activate_calls) == 1
    assert not future.done()

    active = fake_nm.active[0]
    active.change_state(NM.ActiveConnectionState.ACTIVATED)
    assert future.result(timeout=0.1) is None
    assert not active.handlers


def test_existing_inactive_profile_is_reused(client):
    existing = _profile("c932e212-b538-4eab-bfe8-f93b45926d48")
    existing.get_setting_connection().props.timestamp = 123
    client._nm_client.profiles.append(existing)
    requested = _profile()

    future = client.add_connection_async(requested)

    assert not client._nm_client.add_calls
    assert client._nm_client.activate_calls[0]["connection"] is existing
    assert requested.get_uuid() == "c4c15886-3df0-42e6-8d24-623b449dafbf"
    client._nm_client.active[0].change_state(
        NM.ActiveConnectionState.ACTIVATED
    )
    assert future.result(timeout=0.1) is None


@pytest.mark.parametrize("state", [
    NM.ActiveConnectionState.ACTIVATED,
    NM.ActiveConnectionState.ACTIVATING,
])
def test_active_or_activating_profile_is_reused(client, state):
    existing = _profile()
    active = _ActiveConnection(existing, state)
    client._nm_client.profiles = [existing]
    client._nm_client.active = [active]

    future = client.add_connection_async(_profile())

    assert not client._nm_client.add_calls
    assert not client._nm_client.activate_calls
    assert future.done() is (state == NM.ActiveConnectionState.ACTIVATED)
    active.change_state(NM.ActiveConnectionState.ACTIVATED)
    assert future.result(timeout=0.1) is None
    assert not active.handlers


def test_profile_comparison_does_not_mutate_request(client):
    existing = _profile("c932e212-b538-4eab-bfe8-f93b45926d48")
    assert existing.normalize()[0]
    client._nm_client.profiles = [existing]
    requested = _profile()
    original = requested.to_dbus(NM.ConnectionSerializationFlags.ALL)

    future = client.add_connection_async(requested)
    client._nm_client.active[0].change_state(
        NM.ActiveConnectionState.ACTIVATED
    )

    assert future.result(timeout=0.1) is None
    assert original == requested.to_dbus(NM.ConnectionSerializationFlags.ALL)


def test_activation_completed_before_reply_is_detected(client):
    client._nm_client.initial_state = NM.ActiveConnectionState.ACTIVATED

    future = client.add_connection_async(_profile(), save_to_disk=True)

    assert future.result(timeout=0.1) is None
    assert client._nm_client.add_calls[0]["save_to_disk"] is True
    assert not client._nm_client.active[0].handlers


def test_autoconnect_racing_add_reply_does_not_reactivate(client):
    client._nm_client.autoconnect_on_add = True

    future = client.add_connection_async(_profile())

    assert not client._nm_client.activate_calls
    client._nm_client.active[0].change_state(
        NM.ActiveConnectionState.ACTIVATED
    )
    assert future.result(timeout=0.1) is None


def test_compatible_duplicates_prefer_active_profile(client):
    first = _profile()
    second = _profile("c932e212-b538-4eab-bfe8-f93b45926d48")
    client._nm_client.profiles = [first, second]
    client._nm_client.active = [
        _ActiveConnection(second, NM.ActiveConnectionState.ACTIVATED)
    ]

    assert client.add_connection_async(_profile()).result(timeout=0.1) is None
    assert not client._nm_client.add_calls
    assert not client._nm_client.activate_calls
    assert client._nm_client.profiles == [first, second]


def test_unrelated_profile_is_untouched(client):
    unrelated = _profile()
    unrelated.get_setting_connection().props.id = "Unrelated VPN"
    client._nm_client.profiles = [unrelated]

    future = client.add_connection_async(_profile())
    client._nm_client.active[0].change_state(
        NM.ActiveConnectionState.ACTIVATED
    )

    assert future.result(timeout=0.1) is None
    assert len(client._nm_client.profiles) == 2
    assert unrelated.get_id() == "Unrelated VPN"


@pytest.mark.parametrize("field", ["dns", "interface", "permissions"])
def test_same_name_with_different_settings_is_rejected(client, field):
    existing = _profile()
    if field == "dns":
        existing.get_setting_ip6_config().add_dns("2001:db8::1")
    elif field == "interface":
        existing.get_setting_connection().props.interface_name = "unrelated0"
    else:
        existing.get_setting_connection().add_permission(
            "user", "other-user", None
        )
    client._nm_client.profiles = [existing]

    future = client.add_connection_async(_profile())

    with pytest.raises(RuntimeError, match="unexpected settings"):
        future.result(timeout=0.1)
    assert not client._nm_client.add_calls
    assert not client._nm_client.activate_calls


@pytest.mark.parametrize("state", [
    NM.ActiveConnectionState.DEACTIVATING,
    NM.ActiveConnectionState.DEACTIVATED,
])
def test_failed_activation_reuses_profile_on_retry(client, state):
    first = client.add_connection_async(_profile())
    client._nm_client.active[-1].change_state(state)
    with pytest.raises(RuntimeError, match="activation failed"):
        first.result(timeout=0.1)

    retry = client.add_connection_async(_profile())
    client._nm_client.active[-1].change_state(NM.ActiveConnectionState.ACTIVATED)
    assert retry.result(timeout=0.1) is None
    assert len(client._nm_client.add_calls) == 1
    assert len(client._nm_client.activate_calls) == 2
    assert len(client._nm_client.profiles) == 1


def test_add_and_activation_errors_complete_future(client):
    client._nm_client.add_error = RuntimeError("add failed")
    with pytest.raises(RuntimeError, match="add failed"):
        client.add_connection_async(_profile()).result(timeout=0.1)

    client._nm_client.add_error = None
    client._nm_client.activate_error = RuntimeError("activation refused")
    with pytest.raises(RuntimeError, match="activation refused"):
        client.add_connection_async(_profile()).result(timeout=0.1)
    assert not client._nm_client.active[-1].handlers


def test_timeout_cancels_glib_work_and_releases_handlers(client):
    future = client.add_connection_async(_profile())

    async def wait_for_timeout():
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(asyncio.wrap_future(future), 0.01)

    asyncio.run(wait_for_timeout())

    assert future.cancelled()
    assert client._nm_client.activate_calls[0]["cancellable"].is_cancelled()
    assert not client._nm_client.active[0].handlers
    assert len(client._nm_client.profiles) == 1

    retry = client.add_connection_async(_profile())
    client._nm_client.active[0].change_state(NM.ActiveConnectionState.ACTIVATED)
    assert retry.result(timeout=0.1) is None
    assert len(client._nm_client.add_calls) == 1


def test_cancelled_add_does_not_dispatch_late_activation(client):
    client._nm_client.hold_add = True
    future = client.add_connection_async(_profile())

    assert future.cancel()
    client._nm_client.add_reply()

    assert not client._nm_client.activate_calls
    assert client._nm_client.add_calls[0]["cancellable"].is_cancelled()


def test_cancelled_activation_does_not_attach_late_handlers(client):
    client._nm_client.hold_activate = True
    future = client.add_connection_async(_profile())

    assert future.cancel()
    client._nm_client.activate_reply()

    assert not client._nm_client.active[0].handlers
