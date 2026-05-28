"""
VPN connector.


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
from __future__ import annotations

import asyncio
from copy import deepcopy
import os
import threading
from typing import Optional, runtime_checkable, Protocol, Iterator

from proton.vpn.connection.persistence import ConnectionPersistence
from proton.vpn.core.refresher import VPNDataRefresher
from proton.vpn.core.session_holder import SessionHolder
from proton.vpn.core.settings import SettingsPersistence
from proton.vpn.core.settings.split_tunneling import SplitTunneling as SplitTunnelingSetting
from proton.vpn.killswitch.interface import KillSwitch

from proton.vpn import logging
from proton.vpn.connection import (
    events, states, VPNConnection, VPNServer, ProtocolPorts, VPNCredentials,
    Settings
)
from proton.vpn.core.registry import Registry
from proton.vpn.connection.enum import KillSwitchSetting, ConnectionStateEnum
from proton.vpn.connection.publisher import Publisher
from proton.vpn.connection.states import StateContext
from proton.vpn.session.client_config import ClientConfig
from proton.vpn.session.dataclasses import VPNLocation
from proton.vpn.session.servers import LogicalServer, ServerFeatureEnum
from proton.vpn.core.usage import UsageReporting
from proton.vpn.connection.exceptions import FeatureSyntaxError, FeatureError
from proton.vpn.split_tunneling.interface import SplitTunneling
from proton.vpn.core.cache_handlers import PortForwardFileHandler

logger = logging.getLogger(__name__)


@runtime_checkable
class VPNStateSubscriber(Protocol):  # pylint: disable=too-few-public-methods
    """Subscriber to connection status updates."""

    def status_update(self, status: "BaseState"):  # noqa
        """This method is called by the publisher whenever a VPN connection status
        update occurs.
        :param status: new connection status.
        """


class VPNConnector:  # pylint: disable=too-many-instance-attributes
    """
    Allows connecting/disconnecting to/from Proton VPN servers, as well as querying
    information about the current VPN connection, or subscribing to its state
    updates.

    Multiple simultaneous VPN connections are not allowed. If a connection
    already exists when a new one is requested then the current one is brought
    down before starting the new one.
    """

    @classmethod
    async def get(  # pylint: disable=too-many-arguments
        cls,
        session_holder: SessionHolder,
        settings_persistence: SettingsPersistence,
        usage_reporting: UsageReporting,
        registry: Registry,
        kill_switch: KillSwitch = None,
    ):
        """
        Builds a VPN connector instance and initializes it.
        """
        split_tunneling = await SplitTunneling.get(os.getuid())
        connector = VPNConnector(
            session_holder,
            settings_persistence,
            kill_switch=kill_switch,
            usage_reporting=usage_reporting,
            split_tunneling=split_tunneling,
            registry=registry
        )
        await connector.initialize_state()
        return connector

    def __init__(  # pylint: disable=too-many-arguments
            self,
            session_holder: SessionHolder,
            settings_persistence: SettingsPersistence,
            usage_reporting: UsageReporting,
            registry: Registry,
            connection_persistence: Optional[ConnectionPersistence] = None,
            state: Optional[states.State] = None,
            kill_switch: Optional[KillSwitch] = None,
            split_tunneling: Optional[SplitTunneling] = None,
            publisher: Optional[Publisher] = None,
            port_forward_file_handler: PortForwardFileHandler = None,
    ):
        self._session_holder = session_holder
        self._settings_persistence = settings_persistence
        self._connection_persistence = connection_persistence or ConnectionPersistence()
        self._current_state = state
        self._kill_switch = kill_switch
        self._split_tunneling = split_tunneling
        self._publisher = publisher or Publisher()
        self._lock = asyncio.Lock()
        self._background_tasks = set()
        self._usage_reporting = usage_reporting
        self._registry = registry
        self._port_forward_file_handler = port_forward_file_handler or PortForwardFileHandler()

        self._publisher.register(self._on_state_change_update_location)
        self._publisher.register(self._port_forward_file_handler.on_state_change_update_port)

    @property
    def is_split_tunneling_available(self) -> bool:
        """Returns if split tunneling is available or not."""
        return bool(self._split_tunneling)

    async def get_settings(self) -> Settings:
        """Returns the user's settings."""
        # Default to free user settings if the session is not loaded yet.
        user_tier = self._session_holder.user_tier or 0
        loop = asyncio.get_running_loop()
        settings = await loop.run_in_executor(
            None, self._settings_persistence.get,
            user_tier
        )

        return settings

    @property
    def credentials(self) -> Optional[VPNCredentials]:
        """Returns the user's credentials."""
        return self._session_holder.vpn_credentials

    def _set_ks_setting(self, ks_setting: KillSwitchSetting, protocol: str):
        StateContext.kill_switch_setting = ks_setting

        if isinstance(self.current_state, states.Disconnected):
            self._set_ks_impl(protocol)

    async def update_credentials(self):
        """
        Updates the credentials of the current connection.

        This is useful when the certificate used for the current connection
        has expired and a new one is needed.
        """
        if self.current_connection:
            logger.info("Updating credentials for current connection.")
            await self.current_connection.update_credentials(self.credentials)

    async def apply_settings(self, settings: Settings):
        """
        Sets the settings to be applied when establishing the next connection and
        applies them to the current connection whenever that's possible.
        """
        ks_setting = KillSwitchSetting(settings.killswitch)
        protocol = settings.protocol
        self._set_ks_setting(ks_setting, protocol)
        await self._apply_kill_switch_setting(ks_setting)

        if self.current_connection:
            await self.current_connection.update_settings(settings)

        st_setting = settings.features.split_tunneling
        self._set_split_tunneling_setting(st_setting)
        # nosemgrep: python.lang.maintainability.is-function-without-parentheses.is-function-without-parentheses  # pylint: disable=line-too-long  # noqa: E501
        if self.is_split_tunneling_available and self.is_connected:
            await self._apply_split_tunneling_settings(st_setting, ks_setting)

    async def _apply_kill_switch_setting(self, kill_switch_setting: KillSwitchSetting):
        """Enables/disables the kill switch depending on the setting value."""
        kill_switch = self._current_state.context.kill_switch

        if kill_switch_setting == KillSwitchSetting.PERMANENT:
            await kill_switch.enable(permanent=True)
            # Since full KS already prevents IPv6 leaks:
            await kill_switch.disable_ipv6_leak_protection()

        elif kill_switch_setting == KillSwitchSetting.ON:
            if isinstance(self._current_state, states.Disconnected):
                await kill_switch.disable()
                await kill_switch.disable_ipv6_leak_protection()
            else:
                await kill_switch.enable(permanent=False)
                # Since full KS already prevents IPv6 leaks:
                await kill_switch.disable_ipv6_leak_protection()

        elif kill_switch_setting == KillSwitchSetting.OFF:
            if isinstance(self._current_state, states.Disconnected):
                await kill_switch.disable()
                await kill_switch.disable_ipv6_leak_protection()
            else:
                await kill_switch.enable_ipv6_leak_protection()
                await kill_switch.disable()

        else:
            raise RuntimeError(f"Unexpected kill switch setting: {kill_switch_setting}")

    async def _apply_split_tunneling_settings(
            self, st_settings: SplitTunnelingSetting, ks_setting: KillSwitchSetting
    ):
        if ks_setting != KillSwitchSetting.OFF:
            logger.warning("Split tunneling is not compatible with the kill switch feature")
            return

        if not st_settings.enabled:
            await self._split_tunneling.clear_config()
        else:
            await self._split_tunneling.set_config(
                st_settings.get_config()
            )

    async def _get_current_connection(self) -> Optional[VPNConnection]:
        """
        :return: the current VPN connection or None if there isn't one.
        """
        loop = asyncio.get_running_loop()
        persisted_parameters = await loop.run_in_executor(None,
                                                          self._connection_persistence.load)
        if not persisted_parameters:
            return None

        if protocol := self._registry.get(persisted_parameters.protocol):
            vpn_connection = protocol(
                server=persisted_parameters.server,
                credentials=self.credentials,
                settings=await self.get_settings(),
                connection_id=persisted_parameters.connection_id,
                user_tier=self._session_holder.user_tier
            )
            if not isinstance(vpn_connection.initial_state, states.Disconnected):
                return vpn_connection

        return None

    async def _get_initial_state(self):
        """Determines the initial state of the state machine."""

        # It's possible that the user is not logged in but that there is
        # a persisted connection, in this case we need to ignore the persisted
        # connection and return the disconnected state.
        if self._session_holder.session.logged_in:
            current_connection = await self._get_current_connection()

            if current_connection:
                return current_connection.initial_state

        return states.Disconnected(
            StateContext(event=events.Initialized(events.EventContext(connection=None)))
        )

    async def initialize_state(self):
        """Initializes the state machine with the specified state."""
        state = await self._get_initial_state()

        settings = await self.get_settings()
        StateContext.kill_switch_setting = KillSwitchSetting(settings.killswitch)
        self._set_ks_impl(settings.protocol)

        self._set_split_tunneling_setting(settings.features.split_tunneling)
        self._set_split_tunneling_impl()

        connection = state.context.connection
        if connection:
            connection.register(self._on_connection_event)

        # Sets the initial state of the connector and triggers the tasks associated
        # to the state.
        await self._update_state(state)

        # Makes sure that the kill switch state is inline with the current
        # kill switch setting (e.g. if the KS setting is set to "permanent" then
        # the permanent KS should be enabled, if it was not the case yet).
        await self._apply_kill_switch_setting(StateContext.kill_switch_setting)

    @property
    def current_state(self) -> states.State:
        """Returns the state of the current VPN connection."""
        return self._current_state

    @property
    def current_connection(self) -> Optional[VPNConnection]:
        """Returns the current VPN connection or None if there isn't one."""
        return self.current_state.context.connection if self.current_state else None

    @property
    def current_server_id(self) -> Optional[str]:
        """
        Returns the server ID of the current VPN connection.

        Note that by if the current state is disconnected, `None` will be
        returned if a VPN connection was never established. Otherwise,
        the server ID of the last server the connection was established to
        will be returned instead.
        """
        return self.current_connection.server_id if self.current_connection else None

    @property
    def is_connection_active(self) -> bool:
        """Returns whether there is currently a VPN connection ongoing or not."""
        return not isinstance(self._current_state, (states.Disconnected, states.Error))

    @property
    def is_connected(self) -> bool:
        """Returns whether the user is connected to a VPN server or not."""
        return isinstance(self.current_state, states.Connected)

    @staticmethod
    def get_vpn_server(
            logical_server: LogicalServer, client_config: ClientConfig
    ) -> VPNServer:
        """
        :return: a :class:`proton.vpn.vpnconnection.interfaces.VPNServer` that
        can be used to establish a VPN connection with
        :class:`proton.vpn.vpnconnection.VPNConnection`.
        """
        physical_server = logical_server.get_random_physical_server()
        has_ipv6_support = ServerFeatureEnum.IPV6 in logical_server.features
        return VPNServer(
            server_ip=physical_server.entry_ip,
            domain=physical_server.domain,
            x25519pk=physical_server.x25519_pk,
            openvpn_ports=ProtocolPorts(
                udp=client_config.openvpn_ports.udp,
                tcp=client_config.openvpn_ports.tcp,
                tls=client_config.openvpn_ports.tls
            ),
            wireguard_ports=ProtocolPorts(
                udp=client_config.wireguard_ports.udp,
                tcp=client_config.wireguard_ports.tcp,
                tls=client_config.wireguard_ports.tls
            ),
            server_id=logical_server.id,
            server_name=logical_server.name,
            has_ipv6_support=has_ipv6_support,
            label=physical_server.label
        )

    def iter_available_protocols(self, protocol_group) -> Iterator[type[VPNConnection]]:
        """Returns an iterator over the available VPN connection protocols."""
        return filter(
            lambda cls: cls.get_protocol_group() == protocol_group,
            self._registry.iter(interface=VPNConnection)
        )

    # pylint: disable=too-many-arguments
    async def connect(
            self, server: VPNServer,
            protocol: str = None,
            backend: str = None
    ):
        """Connects to a VPN server."""
        if not self._session_holder.session.logged_in:
            raise RuntimeError("Log in required before starting VPN connections.")

        logger.info(
            f"{server} / Protocol: {protocol} / Backend: {backend}",
            category="CONN", subcategory="CONNECT", event="START"
        )

        # Sets the settings to be applied when establishing the next connection.
        settings = await self.get_settings()
        # FIXME: this adds a big delay before creating the connection  # pylint: disable=fixme
        self._set_ks_setting(KillSwitchSetting(settings.killswitch), settings.protocol)
        self._set_split_tunneling_setting(settings.features.split_tunneling)

        protocol = protocol or settings.protocol

        protocol_type = self._registry.get(protocol)

        connection = protocol_type(
            server, self.credentials, settings, self._session_holder.user_tier)

        connection.register(self._on_connection_event)

        await self._on_connection_event(
            events.Up(events.EventContext(connection=connection))
        )

    async def disconnect(self):
        """Disconnects the current VPN connection, if any."""
        await self._on_connection_event(
            events.Down(events.EventContext(connection=self.current_connection))
        )

    def register(self, subscriber: VPNStateSubscriber):
        """
        Registers a new subscriber to connection status updates.

        The subscriber should have a ```status_update``` method, which will
        be called passing it the new connection status whenever it changes.

        :param subscriber: Subscriber to register.
        """
        if not isinstance(subscriber, VPNStateSubscriber):
            raise ValueError(
                "The specified subscriber does not implement the "
                f"{VPNStateSubscriber.__name__} protocol."
            )
        self._publisher.register(subscriber.status_update)

    def unregister(self, subscriber: VPNStateSubscriber):
        """
        Unregister a subscriber from connection status updates.
        :param subscriber: Subscriber to unregister.
        """
        if not isinstance(subscriber, VPNStateSubscriber):
            raise ValueError(
                "The specified subscriber does not implement the "
                f"{VPNStateSubscriber.__name__} protocol."
            )
        self._publisher.unregister(subscriber.status_update)

    async def _handle_on_event(self, event: events.Event):
        """
        Handles the event by updating the current state of the connection,
        and returning a new event to be processed if any.
        """
        try:
            new_state = self.current_state.on_event(event)
        except FeatureSyntaxError as excp:
            self._usage_reporting.report_error(excp)
            logger.exception(msg=excp.message)
        except FeatureError as excp:
            logger.warning(msg=excp.message)
        except Exception as excp:
            self._usage_reporting.report_error(excp)
            raise excp
        else:
            return await self._update_state(new_state)
        return None

    async def _on_connection_event(self, event: events.Event):
        """
        Callback called when a connection event happens.
        """
        # The following lock guaranties that each new event is processed only
        # when the previous event was fully processed.
        async with self._lock:
            triggered_events = 0
            while event:
                triggered_events += 1
                if triggered_events > 99:
                    raise RuntimeError("Maximum number of chained connection events was reached.")
                event = await self._handle_on_event(event)

    async def _update_state(self, new_state) -> Optional[events.Event]:
        if new_state is self.current_state:
            return None

        old_state = self._current_state

        if isinstance(new_state.context.event, events.TwoFARequired) and \
           isinstance(old_state.context.event, events.TwoFARequired):
            return None

        self._current_state = new_state

        logger.info(
            f"{type(self._current_state).__name__}"
            f"{' (initial state)' if not old_state else ''}",
            category="CONN", event="STATE_CHANGED"
        )

        if isinstance(self._current_state, states.Disconnected) \
                and self._current_state.context.connection:
            # Unregister from connection event updates once the connection ended.
            self._current_state.context.connection.unregister(self._on_connection_event)

        if isinstance(old_state, states.Connected) and isinstance(new_state, states.Connected):
            # A Connected state can transition to a new Connected state when local agent
            # sends a new connected event, e.g. with a new port forwarding port. In this case,
            # the connection subscribers are notified (to update data on the client UI)
            # but the tasks associated with the connected state do not need to be run again
            # since the connection state didn't really change, only its context data did.
            self._publisher.notify(new_state)
            return None

        if self._current_state.notify_early:
            self._publisher.notify(new_state)
            new_event = await self._current_state.run_tasks()
        else:
            new_event = await self._current_state.run_tasks()
            self._publisher.notify(new_state)

        if (
            not self._current_state.context.reconnection
            and isinstance(self._current_state, states.Disconnected)
        ):
            self._set_ks_impl((await self.get_settings()).protocol)

        return new_event

    def _on_state_change_update_location(self, state: states.State):
        """Updates the user location when the connection is established."""
        connection_details = self._get_connection_details_from_state(state)
        if not connection_details:
            return

        current_location = self._session_holder.session.vpn_account.location

        self._session_holder.session.set_location(
            self._create_new_vpn_location(connection_details, current_location)
        )

    def _get_connection_details_from_state(
            self, state: states.State
    ) -> Optional[events.ConnectionDetails]:
        if not isinstance(state, states.Connected):
            return None

        connection_details = state.context.event.context.connection_details
        if not connection_details or not connection_details.device_ip:
            return None

        return connection_details

    def _create_new_vpn_location(self, connection_details, current_location) -> VPNLocation:
        return VPNLocation(
            IP=connection_details.device_ip,
            Country=connection_details.device_country,
            ISP=current_location.ISP,
            Long=current_location.Long,
            Lat=current_location.Lat
        )

    def _set_ks_impl(self, protocol: str):
        """
        By using this specific method we're leaking implementation details.

        Because we currently have to deal with two kill switch NetworkManager implementations,
        one for OpenVPN and one for WireGuard, and them not being compatible with each other,
        we need to ensure that when switching protocols,
        we only do this when we are in `Disconnected` state, to ensure
        that the environment is clean and we don't leave any residuals on a users machine.
        """
        kill_switch_backend = KillSwitch.get(protocol=protocol)
        StateContext.kill_switch = self._kill_switch or kill_switch_backend()

    def _set_split_tunneling_setting(self, st_setting: SplitTunnelingSetting):

        st_setting = deepcopy(st_setting)
        st_setting.enabled = (
            self._split_tunneling
            and st_setting.enabled
            and not self._is_free_tier()
        )

        StateContext.split_tunneling_setting = st_setting

    def _set_split_tunneling_impl(self):
        StateContext.split_tunneling = self._split_tunneling

    def _get_user_tier(self) -> int:
        # Default to free tier if session is not loaded yet
        return self._session_holder.user_tier or 0

    def _is_free_tier(self) -> bool:
        return self._get_user_tier() == 0

    def subscribe_to_certificate_updates(self, refresher: VPNDataRefresher):
        """Subscribes to certificate updates."""
        refresher.set_certificate_updated_callback(self._on_certificate_updated)

    async def _on_certificate_updated(self):
        """Actions to be taken when once the certificate is updated."""
        if isinstance(self.current_state, (states.Connected, states.Error)):
            await self.update_credentials()


class Subscriber:
    """
    Connection subscriber implementation that allows blocking until a certain state is reached.
    """
    def __init__(self):
        self.state: ConnectionStateEnum = None
        self.events = {state: threading.Event() for state in ConnectionStateEnum}

    def status_update(self, state):
        """
        This method will be called whenever a VPN connection state update occurs.
        :param state: new state.
        """
        self.state = state.type
        self.events[self.state].set()
        self.events[self.state].clear()

    def wait_for_state(self, state: ConnectionStateEnum, timeout: int = None):
        """
        Blocks until the specified VPN connection state is reached.

        :param state: target connection state.
        :param timeout: if specified, a TimeoutError will be raised
        when the target state is reached.
        """
        state_reached = self.events[state].wait(timeout)
        if not state_reached:
            raise TimeoutError(f"Time out occurred before reaching state {state.name}.")
