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
import logging
from concurrent.futures import Future
from threading import Thread, Lock
from typing import Callable, Optional
from packaging import version
from packaging.version import Version

import gi
gi.require_version("NM", "1.0")  # noqa: required before importing NM module
# pylint: disable=wrong-import-position
from gi.repository import NM, GLib

from proton.vpn.connection.exceptions import VPNConnectionError

logger = logging.getLogger(__name__)


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
        cls._nm_client = NM.Client()
        # Setting daemon=True when creating the thread makes that this thread
        # exits abruptly when the python process exits. It would be better to
        # exit the thread running the main loop calling self._main_loop.quit().
        Thread(target=cls._run_main_loop, daemon=True).start()

        callback, future = cls.create_nmcli_callback(
            finish_method_name="new_finish"
        )

        def new_async():
            cls._assert_running_on_main_loop_thread()
            cls._nm_client.new_async(cancellable=None, callback=callback, user_data=None)

        cls._run_on_main_loop_thread(new_async)
        cls._nm_client = future.result()

    @classmethod
    def _run_main_loop(cls):
        main_loop = GLib.MainLoop(cls._main_context)
        cls._main_context.push_thread_default()
        main_loop.run()

    @classmethod
    def _assert_running_on_main_loop_thread(cls):
        """
        This method asserts that the thread running it is the one iterating
        GLib's main loop.

        It's useful to call this method at the beginning of any code block
        that's supposed to run in GLib's main loop, to avoid hard-to-debug
        issues.

        For more info:
        https://developer.gnome.org/documentation/tutorials/main-contexts.html#checking-threading
        """
        assert cls._main_context.is_owner()  # nosec B311, B101 # noqa: E501 # pylint: disable=line-too-long # nosemgrep: gitlab.bandit.B101

    @classmethod
    def _run_on_main_loop_thread(cls, function):
        cls._main_context.invoke_full(priority=GLib.PRIORITY_DEFAULT, function=function)

    @classmethod
    def create_nmcli_callback(cls, finish_method_name: str) -> (Callable, Future):
        """Creates a callback for the NM client finish method and a Future that will
        resolve once the callback is called."""
        future = Future()
        future.set_running_or_notify_cancel()

        def callback(source_object, res, userdata):  # pylint: disable=unused-argument
            cls._assert_running_on_main_loop_thread()
            try:
                # On errors, according to the docs, the callback can be called
                # with source_object/res set to None.
                # https://lazka.github.io/pgi-docs/index.html#NM-1.0/classes/Client.html#NM.Client.new_async
                if not source_object or not res:

                    raise VPNConnectionError(
                        f"An unexpected error occurred initializing NMClient: "
                        f"source_object = {source_object}, res = {res}."
                    )

                result = getattr(source_object, finish_method_name)(res)

                # According to the docs, None is returned on errors
                # https://lazka.github.io/pgi-docs/index.html#NM-1.0/classes/Client.html#NM.Client.new_finish
                if not result:
                    raise VPNConnectionError(
                        "An unexpected error occurred initializing NMCLient"
                    )

                future.set_result(result)
            except BaseException as exc:  # pylint: disable=broad-except
                future.set_exception(exc)

        return callback, future

    def __init__(self):
        self.initialize_nm_client_singleton()

    def _get_nm_daemon_version(self) -> Optional[Version]:
        """
        Gets the version of Network manager daemon running on the host system
        or None if not detected.
        """
        version_string = self._nm_client.get_version()
        return version.parse(version_string) if version_string else None

    def _get_nm_client_version(self) -> Version:
        """
        Get the version of Network manager client.
        """
        return version.parse(f"{NM.MAJOR_VERSION}.{NM.MINOR_VERSION}.{NM.MICRO_VERSION}")

    @staticmethod
    def is_version_compatible(client_version: Version, daemon_version: Optional[Version]) -> bool:
        """
        Checks for compatibility between network manager daemon and network manager client
        Takes versions as arguments for testability
        """
        if daemon_version is None:
            logger.warning("NetworkManager daemon is not found")
            return False
        threshold = version.parse("1.46")
        # Incompatible: has_autoconnect_ports=True but NM daemon version < 1.46
        # This is the issue with snaps on hosts systems that are older than the base snap
        if client_version >= threshold > daemon_version:
            logger.warning(
                "NM daemon version is %s (requires >= 1.46 when autoconnect_ports is supported)",
                daemon_version
            )
            return False
        return True

    def is_nm_version_compatible(self) -> bool:
        """
        Checks for compatibility between running network manager daemon and network manager client.
        """
        return self.is_version_compatible(
            self._get_nm_client_version(),
            self._get_nm_daemon_version()
        )

    def commit_changes_async(
            self, new_connection: NM.RemoteConnection
    ) -> Future:
        """
        Commits changes asynchronously.
        https://lazka.github.io/pgi-docs/#NM-1.0/classes/RemoteConnection.html#NM.RemoteConnection.commit_changes_async
        :return: a Future to keep track of completion.
        """
        callback, future = self.create_nmcli_callback(
            finish_method_name="commit_changes_finish"
        )

        def commit_changes_async():
            self._assert_running_on_main_loop_thread()
            new_connection.commit_changes_async(
                True,
                None,
                callback,
                None
            )

        self._run_on_main_loop_thread(commit_changes_async)
        return future

    def add_connection_async(self, connection: NM.Connection) -> Future:
        """
        Adds a new connection asynchronously.
        https://lazka.github.io/pgi-docs/#NM-1.0/classes/Client.html#NM.Client.add_connection_async
        :param connection: connection to be added.
        :return: a Future to keep track of completion.
        """
        callback, future = self.create_nmcli_callback(
            finish_method_name="add_connection_finish"
        )

        def add_connection_async():
            self._assert_running_on_main_loop_thread()
            self._nm_client.add_connection_async(
                connection=connection,
                save_to_disk=False,
                cancellable=None,
                callback=callback,
                user_data=None
            )

        self._run_on_main_loop_thread(add_connection_async)
        return future

    def start_connection_async(
            self, connection: NM.Connection,
            infer_parent_connection: bool = False
    ) -> Future:
        """Starts a VPN connection asynchronously.
        :param connection: connection to be started.
        :param infer_parent_connection: when True, the physical active connection
        with the lowest default route metric is passed as specific_object to NM.
        Required for VPN plugin connections (e.g. ProTun) when the kill switch
        dummy interface would otherwise become the parent device.
        :return: Future to know when the connection has been started. Note that
        is just after the connection has started but before it is established.
        """
        callback, future = self.create_nmcli_callback(
            finish_method_name="activate_connection_finish"
        )

        if infer_parent_connection:
            physical_ac = self.find_best_parent_connection()
            specific_object = physical_ac.get_path() if physical_ac else None
        else:
            specific_object = None

        def activate_connection_async():
            self._assert_running_on_main_loop_thread()
            self._nm_client.activate_connection_async(
                connection,
                None,
                specific_object,
                None,
                callback,
                None
            )

        self._run_on_main_loop_thread(activate_connection_async)
        return future

    def find_best_parent_connection(self) -> Optional[NM.ActiveConnection]:
        """Find the best parent connection for a vpn connection, or None if
        one can't be found."""

        best: Optional[NM.ActiveConnection] = None

        # The metric field is a 32 bit unsigned int. So the largest possible
        # value is (2^32) - 1.
        # For a breakdown of each struct see
        # https://kernelspec.blogspot.com/2014/10/zoom-into-packet-routing-in-linux-kernel.html
        # or look at Chapter 5 (The IPv4 Routing Subsystem) of "Linux Kernel Networking"
        # by Rami Rosen, the metric field is called fib_priority and its in
        # the fib_info struct.
        # Direct reference to the structure in the linux kernel codebase is
        # here:
        # https://github.com/torvalds/linux/blob/master/include/net/ip_fib.h#L136
        best_metric: int = (1 << 32) - 1  # Largest/Worst possible metric

        def is_default_route(route):
            return route.get_dest() == "0.0.0.0" and route.get_prefix() == 0  # nosec B104

        def is_physical_connection(active_connection):
            return active_connection.props.type in (
                NM.SETTING_WIRED_SETTING_NAME,     # Ethernet/USB+Ethernet
                NM.SETTING_WIRELESS_SETTING_NAME,  # Wifi
                NM.SETTING_GSM_SETTING_NAME,       # USB+Dongle
                NM.SETTING_CDMA_SETTING_NAME,      # USB+Dongle
                NM.SETTING_BRIDGE_SETTING_NAME     # Bridge
            )

        for active_connection in self._nm_client.get_active_connections():
            # Only allow physical connections
            if not is_physical_connection(active_connection):
                continue

            # Filter based on ipv4 config, as our vpn traffic goes over ipv4,
            # even the ipv6 traffic.
            ip4_config = active_connection.get_ip4_config()
            if ip4_config is None:
                continue

            # Here we're searching for default routes only,
            # because these are the routes that the vpn tunnel
            # will rely on to get encrypted traffic out to the wide world.
            #
            # We're searching for the best default route and returning the
            # connection associated with that.
            #
            # This is intended for use by wireguard based vpn plugins only.
            # In standard wireguard routing, the default routes in the main
            # table are the routes out of the machine.
            for route in ip4_config.get_routes():
                if is_default_route(route):
                    metric = route.get_metric()
                    if metric < best_metric:
                        best = active_connection
                        best_metric = metric
                    break

        return best

    def stop_connection_async(self, connection: NM.ActiveConnection) -> Future:
        """Stops a VPN connection asynchronously.
        :param connection: connection to be stopped.
        :return: Future to know when the connection has been stopped.
        """
        callback, future = self.create_nmcli_callback(
            finish_method_name="deactivate_connection_finish"
        )

        def deactivate_connection_async():
            self._assert_running_on_main_loop_thread()
            self._nm_client.deactivate_connection_async(
                connection,
                None,
                callback,
                None
            )

        self._run_on_main_loop_thread(deactivate_connection_async)
        return future

    def remove_connection_async(
            self, connection: NM.RemoteConnection
    ) -> Future:
        """
        Removes the specified connection asynchronously.
        https://lazka.github.io/pgi-docs/#NM-1.0/classes/RemoteConnection.html#NM.RemoteConnection.delete_async
        :param connection: connection to be removed.
        :return: a Future to keep track of completion.
        """
        callback, future = self.create_nmcli_callback(
            finish_method_name="delete_finish"
        )

        def delete_async():
            self._assert_running_on_main_loop_thread()
            connection.delete_async(
                None,
                callback,
                None
            )

        self._run_on_main_loop_thread(delete_async)
        return future

    def get_active_connection(self, uuid: str) -> Optional[NM.ActiveConnection]:
        """
        Returns the specified active connection, if existing.
        :param uuid: UUID of the active connection.
        :return: the active connection if it was found. Otherwise, None.
        """
        active_connections = self._nm_client.get_active_connections()

        for connection in active_connections:
            if connection.get_uuid() == uuid:
                return connection

        return None

    def get_connection(self, uuid: str) -> Optional[NM.RemoteConnection]:
        """
        Returns the specified connection, if existing.
        :param uuid: UUID of the connection.
        :return: the connection if it was found. Otherwise, None.
        """
        return self._nm_client.get_connection_by_uuid(uuid)
