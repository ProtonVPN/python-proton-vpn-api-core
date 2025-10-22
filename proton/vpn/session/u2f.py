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
import asyncio
from getpass import getpass
from threading import Event
from typing import Iterator, Optional

from proton.vpn.session import fido2_handler
from proton.session import Session
from proton.session.api import Fido2AssertionParameters, Fido2Assertion
from proton.vpn.session.exceptions import (
    SecurityKeyError, Fido2NotSupportedError,
    SecurityKeyNotFoundError, InvalidSecurityKeyError,
    SecurityKeyPINInvalidError, SecurityKeyPINNotSetError,
    SecurityKeyTimeoutError
)
from proton.vpn.session.u2f_interaction import UserInteraction


from fido2.hid import CtapHidDevice    # pylint: disable=wrong-import-order
# pylint: disable=no-name-in-module
from fido2.client import (             # pylint: disable=wrong-import-order
    Fido2Client, ClientError, UserInteraction as Fido2UserInteraction
)
from fido2.ctap import CtapError       # pylint: disable=wrong-import-order
from fido2.ctap2.pin import ClientPin  # pylint: disable=wrong-import-order


class Fido2UserInteractionAdaptor(Fido2UserInteraction):
    """
    Wraps a UserInteraction object to provide the Fido2UserInteraction
    interface.

    See UserInteraction in fido2.client for details.
    """
    def __init__(self, user_interaction: UserInteraction):
        """Initialize the adaptor with the given UserInteraction object."""
        self._user_interaction = user_interaction

    def prompt_up(self) -> None:
        """Called when the authenticator is awaiting a user presence check."""
        self._user_interaction.prompt_up()

    def request_pin(
        self, permissions: ClientPin.PERMISSION, rp_id: Optional[str]
    ) -> Optional[str]:
        """Called when the client requires a PIN from the user"""
        return self._user_interaction.request_pin(permissions, rp_id)

    def request_uv(
        self, permissions: ClientPin.PERMISSION, rp_id: Optional[str]
    ) -> bool:
        """Called when the client is about to request UV from the user."""
        return self._user_interaction.request_uv(permissions, rp_id)


class U2FKeys:
    """Manage U2F keys."""

    def list_devices(self) -> Iterator[CtapHidDevice]:
        """List all connected FIDO2 devices."""
        return CtapHidDevice.list_devices()

    async def scan_keys_and_get_assertion(
            self,
            session: Session,
            user_interaction: Optional[UserInteraction] = None,
            cancel_assertion: Optional[Event] = None
    ) -> Fido2Assertion:
        """
        Select a FIDO2 client and get an assertion from it.
        :param session: user session.
        :param user_interaction: optional object handling any required user interaction.
        :param cancel_assertion: optional event to be able to cancel the ongoing assertion.
        :returns: the generated FIDO2 assertion.
        """
        if not session.supports_fido2:
            raise Fido2NotSupportedError("Session does not support FIDO2 authentication")

        origin = "https://" + session.supports_fido2.rp_id
        fido2_clients = [
            # pylint: disable=unexpected-keyword-arg
            fido2_handler.create_client(
                device,
                origin,
                Fido2UserInteractionAdaptor(user_interaction)
                if user_interaction else Fido2UserInteraction()
            )
            for device in self.list_devices()
        ]

        if not fido2_clients:
            raise SecurityKeyNotFoundError("No security key found")

        if len(fido2_clients) == 1:
            selected_client = fido2_clients[0]
        else:
            user_interaction.request_key_selection()
            selected_client = await self._touch_key_to_use(fido2_clients)

        assertion_parameters = session.supports_fido2
        cancel_assertion = cancel_assertion or Event()
        return await self.get_assertion_from_client(
            selected_client, assertion_parameters, cancel_assertion
        )

    async def get_assertion_from_client(
            self,
            client: Fido2Client,
            assertion_parameters: Fido2AssertionParameters,
            cancel_assertion: Event
    ) -> Fido2Assertion:
        """Get an assertion from the given FIDO2 client."""
        options = fido2_handler.create_options(assertion_parameters)
        try:
            assertion_selection = await asyncio.to_thread(
                client.get_assertion, options, cancel_assertion
            )
        except ClientError as error:
            if error.code == ClientError.ERR.DEVICE_INELIGIBLE:
                raise InvalidSecurityKeyError("The security key is not eligible") from error

            if error.code == ClientError.ERR.TIMEOUT:
                raise SecurityKeyTimeoutError("The security key operation timed out") from error

            if error.code == ClientError.ERR.CONFIGURATION_UNSUPPORTED:
                raise SecurityKeyPINNotSetError(
                    "The security key doesn't have a PIN set but the server requires it"
                ) from error

            if (
                error.code == ClientError.ERR.BAD_REQUEST
                and isinstance(error.cause, CtapError)
                and error.cause.ERR.PIN_INVALID
            ):
                raise SecurityKeyPINInvalidError(
                    "The security key PIN provided is not valid"
                ) from error

            raise SecurityKeyError("An error occurred with the security key") from error

        except OSError as error:
            # if the key is removed while the client is waitint for it to be touched we get:
            # OSError: [Errno 19] No such device
            raise SecurityKeyNotFoundError("The security key could not be accessed") from error

        except Exception as error:
            raise SecurityKeyError("An error occcurred with the security key") from error

        return fido2_handler.create_from_client_assertion(assertion_selection)

    async def _touch_key_to_use(self, fido2_clients: list[Fido2Client]) -> Fido2Client:
        cancel_key_selection = Event()

        tasks = [
            asyncio.create_task(asyncio.to_thread(
                self._client_selection, client, cancel_key_selection
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


class CLIUserInteraction:
    """
    Provides user interaction via CLI to the Fido2 client.

    The interface currently follows the fido2.client.UserInteraction interface,
    adding some methods to it.
    """

    def prompt_up(self) -> None:
        """Called when the authenticator is awaiting a user presence check."""
        print("If your security key has a button or a gold disc, tap it now to authenticate.")

    def request_pin(
        self, *_args, **_kwargs
    ) -> Optional[str]:
        """Called when the client requires a PIN from the user.

        Should return a PIN, or None/Empty to cancel."""
        return getpass("Introduce your PIN and press enter: ")

    def request_uv(self, *_args, **_kwargs) -> bool:
        """Called when the client is about to request UV from the user.

        Should return True if allowed, or False to cancel."""
        return True

    def request_key_selection(self):
        """Called when multiple keys are found and the user needs to select one
        by touching it."""
        print(
            "Multiple security keys were detected. "
            "If your security key has a button or a gold disc, tap it now to select it."
        )


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
    assertion = await manager.scan_keys_and_get_assertion(session, CLIUserInteraction())

    print("FIDO2 assertion:", assertion)
    result = await session.async_validate_2fa_fido2(assertion)
    if result:
        print("2FA successful, session is now fully authenticated.")
    else:
        print("2FA failed.")
    await session.async_logout()


if __name__ == "__main__":
    asyncio.run(main())
