"""
VPN connection events to react to.


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

from dataclasses import dataclass
from typing import Any, TYPE_CHECKING, Optional

from .enum import StateMachineEventEnum

if TYPE_CHECKING:
    from proton.vpn.connection.vpnconnection import VPNConnection


# pylint: disable=too-few-public-methods

@dataclass
class EventContext:
    """
    Relevant event context.

    It should always contain the VPN connection that emitted the event.
    """

    connection: "VPNConnection"
    error: Optional[Any] = None


class Event:
    """Base event that all the other events should inherit from."""
    type = None

    def __init__(self, context: EventContext = None):
        if self.type is None:
            raise AttributeError("event attribute not defined")

        self.context = context or EventContext(connection=None)


class Initialized(Event):
    """Event that leads to the initial state."""
    type = StateMachineEventEnum.INITIALIZED


class Up(Event):
    """Signals that the VPN connection should be started."""
    type = StateMachineEventEnum.UP


class Down(Event):
    """Signals that the VPN connection should be stopped."""
    type = StateMachineEventEnum.DOWN


class Connected(Event):
    """Signals that the VPN connection was successfully established."""
    type = StateMachineEventEnum.CONNECTED


class Disconnected(Event):
    """Signals that the VPN connection was successfully disconnected by the user."""
    type = StateMachineEventEnum.DISCONNECTED


class Error(Event):
    """Parent class for events signaling VPN disconnection."""


class DeviceDisconnected(Error):
    """Signals that the VPN connection dropped unintentionally."""
    type = StateMachineEventEnum.DEVICE_DISCONNECTED


class Timeout(Error):
    """Signals that a timeout occurred while trying to establish the VPN
    connection."""
    type = StateMachineEventEnum.TIMEOUT


class AuthDenied(Error):
    """Signals that an authentication denied occurred while trying to establish
    the VPN connection."""
    type = StateMachineEventEnum.AUTH_DENIED


class TunnelSetupFailed(Error):
    """Signals that there was an error setting up the VPN tunnel."""
    type = StateMachineEventEnum.TUNNEL_SETUP_FAILED


class UnexpectedError(Error):
    """Signals that an unexpected error occurred."""
    type = StateMachineEventEnum.UNEXPECTED_ERROR


_event_types = [
    event_type for event_type in Event.__subclasses__()
    if event_type is not Error  # As error is an abstract class.
]
_event_types.extend(Error.__subclasses__())
EVENT_TYPES = tuple(_event_types)
