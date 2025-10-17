"""
FIDO2 2.x API implementation for ProtonVPN session handling.

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
# pylint: disable=no-name-in-module
from fido2.hid import CtapHidDevice
from fido2.client import (Fido2Client, DefaultClientDataCollector,
                          UserInteraction as Fido2UserInteraction,
                          AssertionSelection)
from fido2.webauthn import (
    PublicKeyCredentialRequestOptions as Options,
    UserVerificationRequirement,
)

from proton.session.api import Fido2AssertionParameters, Fido2Assertion


def create_client(device: CtapHidDevice,
                  origin: str,
                  user_interaction: Fido2UserInteraction) -> Fido2Client:
    """Create a FIDO2 client for the given device."""

    collector = DefaultClientDataCollector(origin)
    return Fido2Client(  # pylint: disable=unexpected-keyword-arg
        device,
        collector,
        user_interaction=user_interaction
    )


def create_options(assertion_parameters: Fido2AssertionParameters) -> Options:
    """Create a FIDO2 options for the given assertion parameters."""

    user_verification = UserVerificationRequirement(
        assertion_parameters.user_verification
    )
    return Options(
        challenge=assertion_parameters.challenge,
        rp_id=assertion_parameters.rp_id,
        allow_credentials=assertion_parameters.allow_credentials,
        user_verification=user_verification
    )


def create_from_client_assertion(assertion: AssertionSelection) -> Fido2Assertion:
    """Create a FIDO2 assertion from the given client assertion."""

    result = assertion.get_response(0)
    return Fido2Assertion(
        client_data=bytes(result.response.client_data),
        authenticator_data=bytes(result.response.authenticator_data),
        signature=bytes(result.response.signature),
        credential_id=result.raw_id
    )
