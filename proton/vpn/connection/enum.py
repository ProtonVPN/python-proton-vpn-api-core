"""VPN connection enums.


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

from enum import auto, Enum, IntEnum


class ConnectionStateEnum(IntEnum):
    """VPN connection states."""
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    DISCONNECTING = 3
    ERROR = 4


class StateMachineEventEnum(Enum):
    """VPN connection events."""
    INITIALIZED = auto()
    UP = auto()
    DOWN = auto()
    CONNECTED = auto()
    DISCONNECTED = auto()
    TIMEOUT = auto()
    AUTH_DENIED = auto()
    TUNNEL_SETUP_FAILED = auto()
    RETRY = auto()
    UNEXPECTED_ERROR = auto()
    DEVICE_DISCONNECTED = auto()


class KillSwitchSetting(IntEnum):
    """Kill switch setting values."""
    OFF = 0
    ON = 1
    PERMANENT = 2
