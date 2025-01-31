"""
Wrapper over the NetworkManager client.


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
# pylint: disable=duplicate-code

from concurrent.futures import Future
from threading import Thread, Lock
from typing import Optional, List

from packaging.version import Version

import gi
gi.require_version("NM", "1.0")
from gi.repository import NM, GLib, Gio, GObject  # pylint: disable=C0413 # noqa: E402

from proton.vpn import logging  # noqa: E402 pylint: disable=wrong-import-position

logger = logging.getLogger(__name__)


class GatewayNotFoundError(Exception):
    """Error raised when trying to obtain the gateway from a device that
    doesn't have one set."""


def _create_future():
    """Creates a future and sets its internal state as running."""
    future = Future()
    future.set_running_or_notify_cancel()
    return future


class NMClient:
    """
    Wrapper over the NetworkManager client.
    It also starts the GLib main loop used by the NetworkManager client.
    """
    _lock = Lock()
    _main_context = None
    _nm_client = None

    @classmethod
    def initialize_nm_client_singleton(cls):
        """
        Initializes the NetworkManager client singleton.

        If the singleton was initialized, this method will do nothing. However,
        if the singleton wasn't initialized it will initialize it, starting
        a new GLib MainLoop.

        A double-checked lock is used to avoid the possibility of multiple
        threads concurrently creating multiple instances of the NM client
        (with their own main loops).
        """
        if cls._nm_client:
            return

        with cls._lock:
            if not cls._nm_client:
                cls._initialize_nm_client_singleton()

    @classmethod
    def _initialize_nm_client_singleton(cls):
        cls._main_context = GLib.MainContext()

        # Setting daemon=True when creating the thread makes that this thread
        # exits abruptly when the python process exits. It would be better to
        # exit the thread running the main loop calling self._main_loop.quit().
        Thread(target=cls._run_glib_loop, daemon=True).start()

        def _init_nm_client():
            # It's important the NM.Client instance is created in the thread
            # running the GLib event loop so that then that's the thread used
            # for all GLib asynchronous operations.
            return NM.Client.new(cancellable=None)

        cls._nm_client = cls._run_on_glib_loop_thread(_init_nm_client).result()

    @classmethod
    def _run_glib_loop(cls):
        main_loop = GLib.MainLoop(cls._main_context)
        cls._main_context.push_thread_default()
        main_loop.run()

    @classmethod
    def _assert_running_on_glib_loop_thread(cls):
        """
        This method asserts that the thread running it is the one i:terating
        GLib's main loop.

        It's useful to call this method at the beginning of any code block
        that's supposed to run in GLib's main loop, to avoid hard-to-debug
        issues.

        For more info:
        https://developer.gnome.org/documentation/tutorials/main-contexts.html#checking-threading
        """
        if not cls._main_context.is_owner():
            raise RuntimeError("Code being run outside GLib's main loop.")

    @classmethod
    def _run_on_glib_loop_thread(cls, function, *args, **kwargs) -> Future:
        future = _create_future()

        def wrapper():
            cls._assert_running_on_glib_loop_thread()
            try:
                future.set_result(function(*args, **kwargs))
            except BaseException as exc:  # pylint: disable=broad-except
                future.set_exception(exc)

        cls._main_context.invoke_full(priority=GLib.PRIORITY_DEFAULT, function=wrapper)

        return future

    def __init__(self):
        self.initialize_nm_client_singleton()
        self._signal_handlers = []

    def add_connection_async(
            self, connection: NM.Connection, save_to_disk: bool = False
    ) -> Future:
        """
        Adds a new connection asynchronously.
        https://lazka.github.io/pgi-docs/#NM-1.0/classes/Client.html#NM.Client.add_connection_async
        :param connection: connection to be added.
        :return: a Future to keep track of completion.
        """
        future_conn_activated = _create_future()

        def _on_interface_state_changed(_device, new_state, _old_state, _reason):
            """
            Monitors kill switch interface state changes and resolves
            the future as soon as the interface reaches the activated state
            """
            logger.debug(
                f"{connection.get_interface_name()} interface state changed "
                f"to {NM.DeviceState(new_state).value_name}"
            )
            if (
                    NM.DeviceState(new_state) == NM.DeviceState.ACTIVATED
                    and not future_conn_activated.done()
            ):
                future_conn_activated.set_result(None)

        def _on_interface_added(_nm_client, device):
            """
            Monitors interface creation. As soon as the kill switch interface
            is created it sets up the call back to monitor interface state changes.
            """
            logger.debug(
                f"{device.get_iface()} interface added in state {device.get_state().value_name}"
            )
            if not device.get_iface() == connection.get_interface_name():
                return

            handler_id = device.connect("state-changed", _on_interface_state_changed)
            future_conn_activated.add_done_callback(
                lambda f: self._run_on_glib_loop_thread(
                    GObject.signal_handler_disconnect, device, handler_id
                ).result()
            )

        def _on_connection_added(nm_client, res, _user_data):
            try:
                # Make sure exceptions creating the connection are passed to the future.
                nm_client.add_connection_finish(res)
            except Exception as exc:  # pylint: disable=broad-except
                future_conn_activated.set_exception(
                    RuntimeError(
                        f"Error adding KS connection: {exc}"
                    ).with_traceback(exc.__traceback__)
                )
                return

        def _add_connection_async():
            # Set up interface connection monitoring, which resolves the future
            # once the kill switch is active.
            handler_id = self._nm_client.connect("device-added", _on_interface_added)
            future_conn_activated.add_done_callback(
                lambda f: self._run_on_glib_loop_thread(
                    GObject.signal_handler_disconnect, self._nm_client, handler_id
                ).result()
            )

            # Add kill switch connection asynchronously.
            self._nm_client.add_connection_async(
                connection=connection,
                save_to_disk=save_to_disk,
                cancellable=None,
                callback=_on_connection_added,
                user_data=None
            )

        self._run_on_glib_loop_thread(_add_connection_async).result()

        return future_conn_activated

    def get_physical_devices(self) -> List[NM.Device]:
        """Returns all the active ethernet/wifi devices."""
        return [
            device for device in self._nm_client.get_devices() if (
                device.get_device_type() in (NM.DeviceType.ETHERNET, NM.DeviceType.WIFI)
                and device.get_state() is NM.DeviceState.ACTIVATED
                and device.get_active_connection()  # Maybe this is redundant.
            )
        ]

    def _is_ethernet_or_wifi_connection(self, active_connection: NM.ActiveConnection):
        return active_connection.props.type in (
            NM.SETTING_WIRED_SETTING_NAME, NM.SETTING_WIRELESS_SETTING_NAME
        )

    def get_ethernet_and_wifi_connections(self) -> List[NM.ActiveConnection]:
        """Returns the list of ethernet and wifi connections."""
        return [
            ac for ac in self._nm_client.get_active_connections()
            if self._is_ethernet_or_wifi_connection(ac)
        ]

    def is_monitoring_network_config_changes(self) -> bool:
        """
        Returns whether monitoring of network configuration changes is already
        enabled or not.
        """
        return bool(self._signal_handlers)

    def start_monitoring_network_config_changes(self, callback):
        """Starts monitoring network configuration changes."""
        if self.is_monitoring_network_config_changes():
            raise RuntimeError("Network config changes are already being monitored.")

        def on_active_connection_changed(active_connection, changed_field):
            if (
                    changed_field.name == NM.DEVICE_IP4_CONFIG
                    and active_connection.get_ip4_config()
                    and active_connection.get_ip4_config().get_gateway()
            ):
                callback(active_connection)

        # Monitor current active (wifi/ethernet) connection changes.
        connections = self.get_ethernet_and_wifi_connections()
        for con in connections:
            handler_id = con.connect("notify", on_active_connection_changed)
            self._signal_handlers.append((con, handler_id))

        def on_active_connection_added(_nm_client, active_connection):
            if self._is_ethernet_or_wifi_connection(active_connection):
                # If the new active connection is a wifi/ethernet connection then
                # start monitoring its config changes.
                handler_id = active_connection.connect("notify", on_active_connection_changed)
                self._signal_handlers.append((active_connection, handler_id))

        # Monitor new active connections.
        handler_id = self._nm_client.connect("active-connection-added", on_active_connection_added)
        self._signal_handlers.append((self._nm_client, handler_id))

    def stop_monitoring_network_config_changes(self):
        """Stops monitoring network configuration changes."""
        for instance, handler_id in self._signal_handlers:
            instance.disconnect(handler_id)

        self._signal_handlers.clear()

    @classmethod
    def _add_ipv4_route(
            cls, active_connection: NM.ActiveConnection,
            server_ip: str, gateway: str
    ):
        cls._assert_running_on_glib_loop_thread()

        connection = active_connection.get_connection()
        config = connection.get_setting_ip4_config()

        config.add_route(
            NM.IPRoute.new(
                family=GLib.SYSDEF_AF_INET,
                dest=server_ip,
                prefix=32,
                next_hop=gateway,
                metric=-1  # -1 just means that the default metric is applied.
            )
        )

    @classmethod
    def _remove_ipv4_routes(
            cls, active_connection: NM.ActiveConnection,
            server_ip: str
    ):
        cls._assert_running_on_glib_loop_thread()

        connection = active_connection.get_connection()
        config = connection.get_setting_ip4_config()

        routes_to_remove = []
        for i in range(config.get_num_routes()):
            route = config.get_route(i)
            if route.get_dest() == server_ip and route.get_prefix() == 32:
                routes_to_remove.append(route)

        for route in routes_to_remove:
            config.remove_route_by_value(route)

    @classmethod
    def _apply_connection_async(
            cls, active_connection: NM.ActiveConnection, future: Future
    ):
        cls._assert_running_on_glib_loop_thread()

        device = active_connection.get_devices()[0]

        def on_device_reapplied(device, result, _data=None):
            try:
                device.reapply_finish(result)
                future.set_result(None)
            except Exception as exc:  # pylint: disable=broad-except
                future.set_exception(exc)

        def on_connection_commited(connection, result, _data=None):
            try:
                connection.commit_changes_finish(result)
                device.reapply_async(
                    # Not sure if it's ok to always pass version_id and flags set to 0.
                    connection, version_id=0, flags=0,
                    cancellable=None, callback=on_device_reapplied
                )
            except Exception as exc:  # pylint: disable=broad-except
                future.set_exception(exc)

        # By not saving the changes to disk, the route is gone after a restart.
        active_connection.get_connection().commit_changes_async(
            save_to_disk=False, cancellable=None, callback=on_connection_commited
        )

    @classmethod
    def add_route_to_device(
            cls, device: NM.Device, new_server_ip: str, old_server_ip: Optional[str] = None
    ) -> Future:
        """
        Adds a route to the device to reach the new server ip via the gateway configured
        on the device.

        :param device: the device to apply the route to.
        :param new_server_ip: the IP to apply the route for.
        :param old_server_ip: if specified, routes for this IP will be removed before
          adding the new one.
        """
        route_added_future = _create_future()
        active_connection = device.get_active_connection()

        def _add_ipv4_route():
            try:
                if old_server_ip:
                    cls._remove_ipv4_routes(active_connection, old_server_ip)

                # Remove any existing routes to the new server that may have been left over.
                cls._remove_ipv4_routes(active_connection, new_server_ip)

                gateway = active_connection.get_ip4_config().get_gateway()
                if not gateway:
                    raise GatewayNotFoundError(
                        "Gateway not found on interface "
                        f"'{device.get_iface()}'"
                    )

                cls._add_ipv4_route(active_connection, new_server_ip, gateway)

                cls._apply_connection_async(active_connection, route_added_future)
            except Exception as exc:  # pylint: disable=broad-except
                route_added_future.set_exception(exc)

        cls._run_on_glib_loop_thread(_add_ipv4_route)

        return route_added_future

    @classmethod
    def remove_route_from_device(cls, device: NM.Device, server_ip: str) -> Future:
        """
        Removes all the routes pointing to the specified server IP
        for the specified device.
        """
        route_removed_future = _create_future()
        active_connection = device.get_active_connection()

        def _remove_ipv4_routes():
            try:
                cls._remove_ipv4_routes(active_connection, server_ip)
                cls._apply_connection_async(active_connection, route_removed_future)
            except Exception as exc:  # pylint: disable=broad-except
                route_removed_future.set_exception(exc)

        cls._run_on_glib_loop_thread(_remove_ipv4_routes)

        return route_removed_future

    def remove_connection_async(
            self, connection: NM.RemoteConnection
    ) -> Future:
        """
        Removes the specified connection asynchronously.
        https://lazka.github.io/pgi-docs/#NM-1.0/classes/RemoteConnection.html#NM.RemoteConnection.delete_async
        :param connection: connection to be removed.
        :return: a Future to keep track of completion.
        """
        future_interface_removed = _create_future()

        def _on_connection_removed(connection, result, _user_data):
            try:
                connection.delete_finish(result)
            except Exception as exc:  # pylint: disable=broad-except
                future_interface_removed.set_exception(
                    RuntimeError(
                        f"Error removing KS connection: {exc}"
                    ).with_traceback(exc.__traceback__)
                )

        def _on_interface_removed(_nm_client, device):
            logger.debug(
                f"{device.get_iface()} was removed."
            )
            if device.get_iface() == connection.get_interface_name():
                future_interface_removed.set_result(None)

        def _remove_connection_async():
            handler_id = self._nm_client.connect("device-removed", _on_interface_removed)
            future_interface_removed.add_done_callback(
                lambda f: self._run_on_glib_loop_thread(
                    GObject.signal_handler_disconnect, self._nm_client, handler_id
                ).result()
            )

            connection.delete_async(
                None,
                _on_connection_removed,
                None
            )

        self._run_on_glib_loop_thread(_remove_connection_async).result()

        return future_interface_removed

    def get_active_connection(self, conn_id: str) -> Optional[NM.ActiveConnection]:
        """
        Returns the specified active connection, if existing.
        :param conn_id: ID of the active connection.
        :return: the active connection if it was found. Otherwise, None.
        """
        def _get_active_connection():
            active_connections = self._nm_client.get_active_connections()

            for connection in active_connections:
                if connection.get_id() == conn_id:
                    return connection

            return None

        return self._run_on_glib_loop_thread(_get_active_connection).result()

    def get_connection(self, conn_id: str) -> Optional[NM.RemoteConnection]:
        """
        Returns the specified connection, if existing.
        :param conn_id: ID of the connection.
        :return: the connection if it was found. Otherwise, None.
        """
        return self._run_on_glib_loop_thread(
            self._nm_client.get_connection_by_id, conn_id
        ).result()

    def get_nm_running(self) -> bool:
        """Returns if NetworkManager daemon is running or not."""
        return self._run_on_glib_loop_thread(
            self._nm_client.get_nm_running
        ).result()

    def connectivity_check_get_enabled(self) -> bool:
        """Returns if connectivity check is enabled or not."""
        return self._run_on_glib_loop_thread(
            self._nm_client.connectivity_check_get_enabled
        ).result()

    def disable_connectivity_check(self) -> Future:
        """Since `connectivity_check_set_enabled` has been deprecated,
        we have to resort to lower lever commands.
        https://lazka.github.io/pgi-docs/#NM-1.0/classes/Client.html#NM.Client.connectivity_check_set_enabled

        This change is necessary since if this feature is enabled,
        dummy connection are inflated with a value of 20000.

        https://developer-old.gnome.org/NetworkManager/stable/NetworkManager.conf.html
        (see under `connectivity section`)
        """
        if Version(self._nm_client.get_version()) < Version("1.24.0"):
            # NM.Client.connectivity_check_set_enabled is deprecated since version 1.22
            # but the replacement method is only available in version 1.24.
            return self._run_on_glib_loop_thread(
                self._nm_client.connectivity_check_set_enabled, False
            )

        return self._dbus_set_property(
            object_path="/org/freedesktop/NetworkManager",
            interface_name="org.freedesktop.NetworkManager",
            property_name="ConnectivityCheckEnabled",
            value=GLib.Variant("b", False),
            timeout_msec=-1,
            cancellable=None
        )

    def _dbus_set_property(  # pylint: disable=too-many-arguments
            self, *userdata, object_path: str, interface_name: str, property_name: str,
            value: GLib.Variant, timeout_msec: int = -1,
            cancellable: Gio.Cancellable = None,
    ) -> Future:
        """Set NM properties since dedicated methods have been deprecated deprecated.
        Source: https://lazka.github.io/pgi-docs/#NM-1.0/classes/Client.html"""  # noqa

        future = _create_future()

        def _on_property_set(nm_client, res, _user_data):
            if not nm_client or not res or not nm_client.dbus_set_property_finish(res):
                future.set_exception(
                    RuntimeError(
                        f"Error disabling network connectivity check: {nm_client=}, {res=}"
                    )
                )
                return

            future.set_result(None)

        def _set_property_async():
            self._assert_running_on_glib_loop_thread()
            self._nm_client.dbus_set_property(
                object_path, interface_name, property_name,
                value, timeout_msec, cancellable, _on_property_set,
                userdata
            )

        self._run_on_glib_loop_thread(_set_property_async).result()

        return future
