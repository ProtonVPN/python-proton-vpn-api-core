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


class NotificationDecodeError(ValueError):
    """Notifications could not be parsed."""


class SecurityKeyError(Exception):
    """Base exception for security key errors."""


class Fido2NotSupportedError(SecurityKeyError):
    """Raised when FIDO2 authentication is not available on the current session."""


class SecurityKeyNotFoundError(SecurityKeyError):
    """Raised when no security key is found."""


class InvalidSecurityKeyError(SecurityKeyError):
    """Raised when the security key is invalid or cannot be used."""


class SecurityKeyTimeoutError(SecurityKeyError):
    """Raised when the security key operation times out."""


class SecurityKeyPINNotSetError(SecurityKeyError):
    """
    Raised when the FIDO 2 server requires a PIN to be set
    on the security key, but the user didn't set it.
    """


class SecurityKeyPINInvalidError(SecurityKeyError):
    """
    Raised when the security key has a PIN set but the one the
    user provided is not correct.
    """
