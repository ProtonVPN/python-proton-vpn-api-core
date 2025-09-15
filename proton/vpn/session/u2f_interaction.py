"""
Copyright (c) 2025 Proton AG

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
from typing import Optional, Protocol


class UserInteraction(Protocol):
    """
    Provides user interaction to the Fido2 client.

    The interface currently follows the fido2.client.UserInteraction interface,
    adding some methods to it.
    """

    def prompt_up(self) -> None:
        """Called when the authenticator is awaiting a user presence check."""

    def request_pin(
        self, *args, **kwargs
    ) -> Optional[str]:
        """Called when the client requires a PIN from the user.

        Should return a PIN, or None/Empty to cancel."""

    def request_uv(self, *args, **kwargs) -> bool:
        """Called when the client is about to request UV from the user.

        Should return True if allowed, or False to cancel."""

    def request_key_selection(self) -> None:
        """Called when multiple keys are found and the user needs to select one
        by touching it."""
