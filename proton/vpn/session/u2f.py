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
# pylint: disable=C0413
from importlib.metadata import version

import asyncio
from getpass import getpass
from threading import Event
from typing import Iterator, Optional

from packaging.version import Version

fido2_version = Version(version("fido2"))
if fido2_version < Version("1.1.2") or fido2_version >= Version("2.0.0"):
    raise ImportError(f"python3-fido2 version {fido2_version} not supported")

from fido2.hid import CtapHidDevice
# pylint: disable=no-name-in-module
from fido2.client import Fido2Client, ClientError, UserInteraction, \
    PublicKeyCredentialRequestOptions

from proton.session import Session
from proton.session.api import Fido2AssertionParameters, Fido2Assertion

from proton.vpn.session.exceptions import (
    SecurityKeyError, Fido2NotSupportedError,
    SecurityKeyNotFoundError, InvalidSecurityKeyError, SecurityKeyTimeoutError
)


class U2FKeys:
    """Manage U2F keys."""

    def list_devices(self) -> Iterator[CtapHidDevice]:
        """List all connected FIDO2 devices."""
        return CtapHidDevice.list_devices()

    async def select_and_get_assertion(self, session: Session):
        """Select a FIDO2 client and get an assertion from it."""
        if not session.supports_fido2:
            raise Fido2NotSupportedError("Session does not support FIDO2 authentication")

        origin = "https://" + session.supports_fido2.rp_id
        fido2_clients = [
            # pylint: disable=unexpected-keyword-arg
            Fido2Client(device, origin, user_interaction=UserInteraction())
            for device in self.list_devices()
        ]

        if not fido2_clients:
            raise SecurityKeyNotFoundError("No security key found")

        if len(fido2_clients) == 1:
            selected_client = fido2_clients[0]
        else:
            print(  # FIXME user interaction  # pylint: disable=fixme
                "Multiple FIDO devices found. Touch one to select it, "
                "then touch it again to proceed..."
            )
            selected_client = await self._touch_key_to_use(fido2_clients)

        assertion_parameters = session.supports_fido2
        return await self.get_assertion(selected_client, assertion_parameters)

    async def get_assertion(self,
                            client: Fido2Client,
                            assertion_parameters: Fido2AssertionParameters) -> Fido2Assertion:
        """Get an assertion from the given FIDO2 client."""
        options = PublicKeyCredentialRequestOptions(
            challenge=assertion_parameters.challenge,
            rp_id=assertion_parameters.rp_id,
            allow_credentials=assertion_parameters.allow_credentials,
            user_verification=assertion_parameters.user_verification
        )
        try:
            assertion_selection = await asyncio.to_thread(client.get_assertion, options)
        except ClientError as error:
            if error.code == ClientError.ERR.DEVICE_INELIGIBLE:
                raise InvalidSecurityKeyError("The security key is not eligible") from error

            if error.code == ClientError.ERR.TIMEOUT:
                raise SecurityKeyTimeoutError("The security key operation timed out") from error

            raise SecurityKeyError("An error occurred with the security key") from error

        response = assertion_selection.get_response(0)
        return Fido2Assertion(
            client_data=bytes(response.client_data),
            authenticator_data=bytes(response.authenticator_data),
            signature=bytes(response.signature),
            credential_id=bytes(response.credential_id)
        )

    async def _touch_key_to_use(self, fido2_clients: list[Fido2Client]) -> Fido2Client:
        cancel_client_selection = Event()

        tasks = [
            asyncio.create_task(asyncio.to_thread(
                self._client_selection, client, cancel_client_selection
            ))
            for client in fido2_clients
        ]

        done_tasks, _ = await asyncio.wait(tasks)
        results = [task.result() for task in done_tasks]
        selected_client = [client for client in results if client is not None].pop()

        return selected_client

    def _client_selection(
            self, client: Fido2Client, cancel_client_selection: Event
    ) -> Optional[Fido2Client]:
        try:
            # Block until user touches the key or event is set
            client.selection(cancel_client_selection)
        except ClientError as error:
            if error.code != ClientError.ERR.TIMEOUT:
                raise
            return None

        # Cancel other client selections
        cancel_client_selection.set()

        # Return the selected client
        return client


async def main():
    """Example usage of the U2FKeys class."""

    session = Session()
    username = input("Enter your username: ")
    password = getpass("Enter your password: ")
    await session.async_authenticate(username=username, password=password)

    if not session.authenticated:
        raise RuntimeError("Authentication failed")

    if not session.needs_twofa:
        raise RuntimeError("Session does not need 2FA")

    print("Scanning for keys...")
    manager = U2FKeys()
    print("Touch your security key to proceed...")
    assertion = await manager.select_and_get_assertion(session)

    print("FIDO2 assertion:", assertion)
    result = await session.async_validate_2fa_fido2(assertion)
    if result:
        print("2FA successful, session is now fully authenticated.")
    else:
        print("2FA failed.")
    await session.async_logout()


if __name__ == "__main__":
    asyncio.run(main())
