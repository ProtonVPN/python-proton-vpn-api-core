"""
The different VPN connection states and their transitions is defined here.


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

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional, ClassVar

from proton.vpn import logging
from proton.vpn.connection import events
from proton.vpn.connection.enum import ConnectionStateEnum, KillSwitchSetting
from proton.vpn.connection.events import EventContext
from proton.vpn.connection.exceptions import ConcurrentConnectionsError
from proton.vpn.killswitch.interface import KillSwitch


if TYPE_CHECKING:
    from proton.vpn.connection.vpnconnection import VPNConnection


logger = logging.getLogger(__name__)


@dataclass
class StateContext:
    """
    Relevant state context data.

    Attributes:
        event: Event that led to the current state.
        connection: current VPN connection. They only case where this
            attribute could be None is on the initial state, if there is not
            already an existing VPN connection.
        reconnection: optional VPN connection to connect to as soon as stopping the current one.
        kill_switch: kill switch implementation.
        kill_switch_setting: on, off, permanent.
    """
    event: events.Event = field(default_factory=events.Initialized)
    connection: Optional["VPNConnection"] = None
    reconnection: Optional["VPNConnection"] = None
    kill_switch: ClassVar[KillSwitch] = None
    kill_switch_setting: ClassVar[KillSwitchSetting] = None


class State(ABC):
    """
    This is the base state from which all other states derive from. Each new
    state has to implement the `on_event` method.

    Since these states are backend agnostic. When implement a new backend the
    person implementing it has to have special care in correctly translating
    the backend specific events to known events
    (see `proton.vpn.connection.events`).

    Each state acts on the `on_event` method. Generally, if a state receives
    an unexpected event, it will then not update the state but rather keep the
    same state and should log the occurrence.

    The general idea of state transitions:

        1) Connect happy path:      Disconnected -> Connecting -> Connected
        2) Connect with error path: Disconnected -> Connecting -> Error
        3) Disconnect happy path:   Connected -> Disconnecting -> Disconnected
        4) Active connection error path: Connected -> Error

    Certain states will have to call methods from the state machine
    (see `Disconnected`, `Connected`). Both of these states call
    `vpn_connection.start()` and `vpn_connection.stop()`.
    It should be noted that these methods should be run in an async way so that
    it does not block the execution of the next line.

    States also have `context` (which are fetched from events). These can help
    in discovering potential issues on why certain states might an unexpected
    behavior. It is worth mentioning though that the contexts will always
    be backend specific.
    """
    type = None

    def __init__(self, context: StateContext = None):
        self.context = context or StateContext()

        if self.type is None:
            raise TypeError("Undefined attribute \"state\" ")

    def _assert_no_concurrent_connections(self, event: events.Event):
        not_up_event = not isinstance(event, events.Up)
        different_connection = event.context.connection is not self.context.connection
        if not_up_event and different_connection:
            # Any state should always receive events for the same connection, the only
            # exception being when the Up event is received. In this case, the Up event
            # always carries a new connection: the new connection to be initiated.
            raise ConcurrentConnectionsError(
                f"State {self} expected events from {self.context.connection} "
                f"but received an event from {event.context.connection} instead."
            )

    def on_event(self, event: events.Event) -> State:
        """Returns the new state based on the received event."""
        self._assert_no_concurrent_connections(event)

        new_state = self._on_event(event)

        if new_state is self:
            logger.warning(
                f"{self.type.name} state received unexpected "
                f"event: {type(event).__name__}",
                category="CONN", event="WARNING"
            )

        return new_state

    @abstractmethod
    def _on_event(
            self, event: events.Event
    ) -> State:
        """Given an event, it returns the new state."""

    async def run_tasks(self) -> Optional[events.Event]:
        """Tasks to be run when this state instance becomes the current VPN state."""


class Disconnected(State):
    """
    Disconnected is the initial state of a connection. It's also its final
    state, except if the connection could not be established due to an error.
    """
    type = ConnectionStateEnum.DISCONNECTED

    def _on_event(self, event: events.Event):
        if isinstance(event, events.Up):
            return Connecting(StateContext(event=event, connection=event.context.connection))

        return self

    async def run_tasks(self):
        # When the state machine is in disconnected state, a VPN connection
        # may have not been created yet.
        if self.context.connection:
            await self.context.connection.remove_persistence()

        if self.context.reconnection:
            # The Kill switch is enabled to avoid leaks when switching servers, even when
            # the kill switch setting is off.
            await self.context.kill_switch.enable()

            # When a reconnection is expected, an Up event is returned to start a new connection.
            # straight away.
            return events.Up(EventContext(connection=self.context.reconnection))

        if self.context.kill_switch_setting == KillSwitchSetting.PERMANENT:
            # This is an abstraction leak of the network manager KS.
            # The only reason for enabling permanent KS here is to switch from the
            # routed KS to the full KS if the user cancels the connection while in
            # Connecting state. Otherwise, the full KS should already be there.
            await self.context.kill_switch.enable(permanent=True)
        else:
            await self.context.kill_switch.disable()
            await self.context.kill_switch.disable_ipv6_leak_protection()

        return None


class Connecting(State):
    """
    Connecting is the state reached when a VPN connection is requested.
    """
    type = ConnectionStateEnum.CONNECTING
    _counter = 0

    def _on_event(self, event: events.Event):
        if isinstance(event, events.Connected):
            return Connected(StateContext(event=event, connection=event.context.connection))

        if isinstance(event, events.Down):
            return Disconnecting(StateContext(event=event, connection=event.context.connection))

        if isinstance(event, events.Error):
            return Error(StateContext(event=event, connection=event.context.connection))

        if isinstance(event, events.Up):
            # If a new connection is requested while in `Connecting` state then
            # cancel the current one and pass the requested connection so that it's
            # started as soon as the current connection is down.
            return Disconnecting(
                StateContext(
                    event=event,
                    connection=self.context.connection,
                    reconnection=event.context.connection
                )
            )

        if isinstance(event, events.Disconnected):
            # Another process disconnected the VPN, otherwise the Disconnected
            # event would've been received by the Disconnecting state.
            return Disconnected(StateContext(event=event, connection=event.context.connection))

        return self

    async def run_tasks(self):
        permanent_ks = self.context.kill_switch_setting == KillSwitchSetting.PERMANENT

        # The reason for always enabling the kill switch independently of the kill switch setting
        # is to avoid leaks when switching servers, even with the kill switch turned off.
        # However, when the kill switch setting is off, the kill switch has to be removed when
        # reaching the connected state.
        await self.context.kill_switch.enable(
            self.context.connection.server,
            permanent=permanent_ks
        )

        await self.context.connection.start()


class Connected(State):
    """
    Connected is the state reached once the VPN connection has been successfully
    established.
    """
    type = ConnectionStateEnum.CONNECTED

    def _on_event(self, event: events.Event):
        if isinstance(event, events.Down):
            return Disconnecting(StateContext(event=event, connection=event.context.connection))

        if isinstance(event, events.Up):
            # If a new connection is requested while in `Connected` state then
            # cancel the current one and pass the requested connection so that it's
            # started as soon as the current connection is down.
            return Disconnecting(
                StateContext(
                    event=event,
                    connection=self.context.connection,
                    reconnection=event.context.connection
                )
            )

        if isinstance(event, events.Error):
            return Error(StateContext(event=event, connection=event.context.connection))

        if isinstance(event, events.Disconnected):
            # Another process disconnected the VPN, otherwise the Disconnected
            # event would've been received by the Disconnecting state.
            return Disconnected(StateContext(event=event, connection=event.context.connection))

        return self

    async def run_tasks(self):
        if self.context.kill_switch_setting == KillSwitchSetting.OFF:
            await self.context.kill_switch.enable_ipv6_leak_protection()
            await self.context.kill_switch.disable()
        else:
            # This is specific to the routing table KS implementation and should be removed.
            # At this point we switch from the routed KS to the full-on KS.
            await self.context.kill_switch.enable(
                permanent=(self.context.kill_switch_setting == KillSwitchSetting.PERMANENT)
            )

        await self.context.connection.add_persistence()


class Disconnecting(State):
    """
    Disconnecting is state reached when VPN disconnection is requested.
    """
    type = ConnectionStateEnum.DISCONNECTING

    def _on_event(self, event: events.Event):
        if isinstance(event, (events.Disconnected, events.Error)):
            # Note that error events signal disconnection from the VPN due to
            # unexpected reasons. In this case, since the goal of the
            # disconnecting state is to reach the disconnected state,
            # both disconnected and error events lead to the desired state.
            if isinstance(event, events.Error):
                logger.warning(
                    "Error event while disconnecting: %s (%s)",
                    type(event).__name__,
                    event.context.error
                )
            return Disconnected(
                StateContext(
                    event=event,
                    connection=event.context.connection,
                    reconnection=self.context.reconnection
                )
            )

        if isinstance(event, events.Up):
            # If a new connection is requested while in the `Disconnecting` state then
            # store the requested connection in the state context so that it's started
            # as soon as the current connection is down.
            self.context.reconnection = event.context.connection

        return self

    async def run_tasks(self):
        await self.context.connection.stop()


class Error(State):
    """
    Error is the state reached after a connection error.
    """
    type = ConnectionStateEnum.ERROR

    def _on_event(self, event: events.Event):
        if isinstance(event, events.Down):
            return Disconnected(StateContext(event=event, connection=event.context.connection))

        if isinstance(event, events.Up):
            return Connecting(StateContext(event=event, connection=event.context.connection))

        return self

    async def run_tasks(self):
        logger.warning(
            "Reached connection error state: %s (%s)",
            type(self.context.event).__name__,
            self.context.event.context.error
        )

        # Make sure connection resources are properly released.
        await self.context.connection.stop()
