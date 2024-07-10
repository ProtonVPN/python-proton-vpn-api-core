"""
Exceptions raised by the VPN connection module.


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


class VPNConnectionError(Exception):
    """Base class for VPN specific exceptions"""
    def __init__(self, message, additional_context=None):
        self.message = message
        self.additional_context = additional_context
        super().__init__(self.message)


class AuthenticationError(VPNConnectionError):
    """When server answers with auth_denied this exception is thrown.

    In many cases, an auth_denied can be thrown for multiple reasons, thus it's up to
    the user to decide how to proceed further.
    """


class ConnectionTimeoutError(VPNConnectionError):
    """When a connection takes too long to connect, this exception will be thrown."""


class MissingBackendDetails(VPNConnectionError):
    """When no VPN backend is found (NetworkManager, Native, etc) then this exception is thrown.

    In rare cases where it can happen that a user has some default packages installed, where the
    services for those packages are actually not running. Ie:
    NetworkManager is installed but not running and for some reason we can't access native backend,
    thus this exception is thrown as we can't do anything.
    """


class MissingProtocolDetails(VPNConnectionError):
    """
    When no VPN protocol is found (OpenVPN, Wireguard, IKEv2, etc) then this exception is thrown.
    """


class ConcurrentConnectionsError(VPNConnectionError):
    """
    Multiple concurrent connections were found, even though only one is allowed at a time.
    """


class UnexpectedError(VPNConnectionError):
    """For any unexpected or unhandled error this exception will be thrown."""
