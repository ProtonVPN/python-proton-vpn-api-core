"""
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


class VPNSessionNotLoadedError(Exception):
    """
    Data from the current VPN session was accessed before it was loaded.
    """


class VPNAccountDecodeError(ValueError):
    """The VPN account could not be deserialized."""


class VPNCertificateError(Exception):
    """
    Base class for certificate errors.
    """


class VPNCertificateExpiredError(VPNCertificateError):
    """
    VPN Certificate is available but is expired.
    """


class VPNCertificateNeedRefreshError(VPNCertificateError):
    """
    VPN Certificate is available but needs to be refreshed because
    is close to expiration.
    """


class VPNCertificateFingerprintError(VPNCertificateError):
    """
    VPN Certificate and private key fingerprint are not matching.
    A new keypair should be generated and the corresponding certificate
    should be fetched from our REST API.
    """


class ServerListDecodeError(ValueError):
    """The server list could not be parsed."""


class ServerNotFoundError(Exception):
    """
    The specified server could not be found in the server list.
    """


class ClientConfigDecodeError(ValueError):
    """The client configuration could not be parsed."""
