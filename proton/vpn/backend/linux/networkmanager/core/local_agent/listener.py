"""
Copyright (c) 2024 Proton AG

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
import asyncio
from collections.abc import Callable
from proton.vpn.local_agent import (  # pylint: disable=no-name-in-module, import-error
    Listener, AgentFeatures, Status
)
from proton.vpn.session.credentials import VPNPubkeyCredentials

from proton.vpn import logging

logger = logging.getLogger(__name__)


class AgentListener:
    """Listens for local agent messages asynchronously."""

    def __init__(self, on_status: Callable[[Status], None], on_error: Callable[[Exception], None]):
        self._listener = None
        self._future = None
        self._on_status_callback = on_status
        self._on_error_callback = on_error

    async def connect(self, domain: str, credentials: VPNPubkeyCredentials):
        """Establishes a connection to local agent server.

        :param domain: the domain of the VPN server.
        :param credentials: object that contains all necessary user credentials.
        :raises ExpiredCertificateError: when the certificate provided is expired or invalid.
        :raises TimeoutError: when the connection to LA server times out.
        :raises Exception: any other exceptions.
        """
        private_key = credentials.get_ed25519_sk_pem()
        certificate = credentials.certificate_pem
        self._listener = await Listener.connect(domain, private_key, certificate)

    async def listen(self):
        """Starts the background process of listening to incoming messages from LA."""
        self._future = self._listener.listen(
            self._on_status_callback, self._on_error_callback
        )
        await self._wait_for_it(self._future)

    async def request_features(self, features: AgentFeatures):
        """Requests the features to be set on the current VPN connection."""
        if features:
            await self._listener.request_features(features)

    async def stop(self):
        """Stops reading incoming messages from LA."""
        if not self._future or self._future.done():
            return

        self._future.cancel()
        await self._wait_for_it(self._future)
        logger.info("Agent listener successfully stopped.")

    @property
    def is_running(self) -> bool:
        """Returns if the future is still running."""
        return self._future and not self._future.done()

    @staticmethod
    async def _wait_for_it(future):
        try:
            await future
        except asyncio.CancelledError:
            pass
