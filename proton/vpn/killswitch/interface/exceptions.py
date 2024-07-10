"""
This module contains the exceptions to be used by kill swtich backends.


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


class KillSwitchException(Exception):
    """Base class for KillSwitch specific exceptions."""

    def __init__(self, message: str, additional_context: object = None):  # noqa
        self.message = message
        self.additional_context = additional_context
        super().__init__(self.message)


class MissingKillSwitchBackendDetails(KillSwitchException):
    """When no KillSwitch backend is found then this exception is raised.

    In rare cases where it can happen that a user has some default packages installed, where the
    services for those packages are actually not running. Ie:
    NetworkManager is installed but not running and for some reason we can't access it,
    thus this exception is raised as we can't do anything.
    """
