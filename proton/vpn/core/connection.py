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
import copy
import threading
from typing import Optional, runtime_checkable, Protocol

from proton.loader import Loader
from proton.loader.loader import PluggableComponent

from proton.vpn.connection.persistence import ConnectionPersistence
from proton.vpn.core.refresher import VPNDataRefresher
from proton.vpn.core.session_holder import SessionHolder
from proton.vpn.core.settings import SettingsPersistence
from proton.vpn.killswitch.interface import KillSwitch

from proton.vpn import logging
from proton.vpn.connection import (
    events, states, VPNConnection, VPNServer, ProtocolPorts,
    VPNCredentials, Settings
)
from proton.vpn.connection.enum import KillSwitchSetting, ConnectionStateEnum
from proton.vpn.connection.publisher import Publisher
from proton.vpn.connection.states import StateContext
from proton.vpn.session.client_config import ClientConfig
from proton.vpn.session.dataclasses import VPNLocation
from proton.vpn.session.servers import LogicalServer, ServerFeatureEnum
from proton.vpn.core.usage import UsageReporting
from proton.vpn.connection.exceptions import FeatureSyntaxError, FeatureError

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
        kill_switch: KillSwitch = None,
    ):
        """
        Builds a VPN connector instance and initializes it.
        """
        connector = VPNConnector(
            session_holder,
            settings_persistence,
            kill_switch=kill_switch,
            usage_reporting=usage_reporting,
        )
        await connector.initialize_state()
        return connector

    def __init__(  # pylint: disable=too-many-arguments
            self,
            session_holder: SessionHolder,
            settings_persistence: SettingsPersistence,
            usage_reporting: UsageReporting,
            connection_persistence: ConnectionPersistence = None,
            state: states.State = None,
            kill_switch: KillSwitch = None,
            publisher: Publisher = None,
    ):
        self._session_holder = session_holder
        self._settings_persistence = settings_persistence
        self._connection_persistence = connection_persistence or ConnectionPersistence()
        self._current_state = state
        self._kill_switch = kill_switch
        self._publisher = publisher or Publisher()
        self._lock = asyncio.Lock()
        self._background_tasks = set()
        self._usage_reporting = usage_reporting

        self._publisher.register(self._on_state_change)

    def _filter_features(self, input_settings: Settings, user_tier: int = None) -> Settings:
        if not user_tier:
            user_tier = self._session_holder.user_tier or 0

        settings = copy.deepcopy(input_settings)

        if self._is_free_tier(user_tier):
            # Our servers do not allow setting connection features on the free
            # tier, not even the defaults.
            settings.features = None

        return settings

    async def get_settings(self) -> Settings:
        """Returns the user's settings."""
        # Default to free user settings if the session is not loaded yet.
        user_tier = self._session_holder.user_tier or 0
        loop = asyncio.get_running_loop()
        settings = await loop.run_in_executor(
            None, self._settings_persistence.get, user_tier
        )

        return self._filter_features(settings, user_tier)

    @property
    def credentials(self) -> Optional[VPNCredentials]:
        """Returns the user's credentials."""
        return self._session_holder.vpn_credentials

    def _set_ks_setting(self, settings: Settings):
        StateContext.kill_switch_setting = KillSwitchSetting(settings.killswitch)

        if isinstance(self.current_state, states.Disconnected):
            self._set_ks_impl(settings)

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
        self._set_ks_setting(settings)
        await self._apply_kill_switch_setting(KillSwitchSetting(settings.killswitch))
        if self.current_connection:

            await self.current_connection.update_settings(
                self._filter_features(settings)
            )

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

    async def _get_current_connection(self) -> Optional[VPNConnection]:
        """
        :return: the current VPN connection or None if there isn't one.
        """
        loop = asyncio.get_running_loop()
        persisted_parameters = await loop.run_in_executor(None, self._connection_persistence.load)
        if not persisted_parameters:
            return None

        # I'm refraining of refactoring the whole thing but this way of loading
        # the protocol class is madness.
        backend_class = Loader.get("backend", persisted_parameters.backend)
        backend_name = backend_class.backend
        if persisted_parameters.backend != backend_name:
            return None

        all_protocols = Loader.get_all(backend_name)
        settings = await self.get_settings()
        for protocol in all_protocols:
            if protocol.cls.protocol == persisted_parameters.protocol:
                vpn_connection = protocol.cls(
                    server=persisted_parameters.server,
                    credentials=self.credentials,
                    settings=settings,
                    connection_id=persisted_parameters.connection_id
                )
                if not isinstance(vpn_connection.initial_state, states.Disconnected):
                    return vpn_connection

        return None

    async def _get_initial_state(self):
        """Determines the initial state of the state machine."""
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
        self._set_ks_impl(settings)

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
                tcp=client_config.openvpn_ports.tcp
            ),
            wireguard_ports=ProtocolPorts(
                udp=client_config.wireguard_ports.udp,
                tcp=client_config.wireguard_ports.tcp
            ),
            server_id=logical_server.id,
            server_name=logical_server.name,
            has_ipv6_support=has_ipv6_support,
            label=physical_server.label
        )

    def get_available_protocols_for_backend(
            self, backend_name: str
    ) -> Optional[PluggableComponent]:
        """Returns available protocols for the `backend_name`

        raises RuntimeError:  if no backends could be found."""
        backend_class = Loader.get("backend", class_name=backend_name)
        supported_protocols = Loader.get_all(backend_class.backend)

        return supported_protocols

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
        self._set_ks_setting(settings)

        protocol = protocol or settings.protocol

        # If IPv6 FF is disabled then the feature should not be toggled client side and
        # should be disabled.
        if not self._can_ipv6_be_toggled_client_side(settings):
            settings.ipv6 = False

        feature_flags = self._session_holder.session.feature_flags
        use_certificate = feature_flags.get("CertificateBasedOpenVPN")

        logger.info("Using certificate based authentication"
                    f" for openvpn: {use_certificate}")

        connection = VPNConnection.create(
            server, self.credentials, settings, protocol, backend,
            use_certificate=use_certificate
        )

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

        new_event = await self._current_state.run_tasks()
        self._publisher.notify(new_state)

        if (
            not self._current_state.context.reconnection
            and isinstance(self._current_state, states.Disconnected)
        ):
            self._set_ks_impl(await self.get_settings())

        return new_event

    def _on_state_change(self, state: states.State):
        """Updates the user location when the connection is established."""
        if not isinstance(state, states.Connected):
            return

        connection_details = state.context.event.context.connection_details
        if not connection_details or not connection_details.device_ip:
            return

        current_location = self._session_holder.session.vpn_account.location
        vpnlocation = VPNLocation(
            IP=connection_details.device_ip,
            Country=connection_details.device_country,
            ISP=current_location.ISP
        )
        self._session_holder.session.set_location(vpnlocation)

    def _set_ks_impl(self, settings: Settings):
        """
        By using this specific method we're leaking implementation details.

        Because we currently have to deal with two kill switch NetworkManager implementations,
        one for OpenVPN and one for WireGuard, and them not being compatible with each other,
        we need to ensure that when switching protocols,
        we only do this when we are in `Disconnected` state, to ensure
        that the environment is clean and we don't leave any residuals on a users machine.
        """
        protocol = settings.protocol
        kill_switch_backend = KillSwitch.get(protocol=protocol)
        StateContext.kill_switch = self._kill_switch or kill_switch_backend()

    def _is_free_tier(self, user_tier: int) -> bool:
        return user_tier == 0

    def _can_ipv6_be_toggled_client_side(self, settings: Settings) -> bool:
        return settings.ipv6 and\
            self._session_holder.session.feature_flags.get("IPv6Support")

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
