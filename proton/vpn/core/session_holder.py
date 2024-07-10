"""
Proton VPN Session API.


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
from __future__ import annotations
from dataclasses import dataclass

import platform
import distro

from proton.sso import ProtonSSO
from proton.vpn import logging
from proton.vpn.session import VPNSession
from proton.vpn.session.utils import to_semver_build_metadata_format

logger = logging.getLogger(__name__)

CPU_ARCHITECTURE = to_semver_build_metadata_format(platform.machine())
DISTRIBUTION_ID = distro.id()
DISTRIBUTION_VERSION = distro.version()


@dataclass
class ClientTypeMetadata:  # pylint: disable=missing-class-docstring
    type: str
    version: str
    architecture: str = CPU_ARCHITECTURE


class SessionHolder:
    """Holds the current session object, initializing it lazily when requested."""

    def __init__(
        self, client_type_metadata: ClientTypeMetadata,
        session: VPNSession = None
    ):
        self._proton_sso = ProtonSSO(
            appversion=self._get_app_version_header_value(client_type_metadata),
            user_agent=f"ProtonVPN/{client_type_metadata.version} "
                       f"(Linux; {DISTRIBUTION_ID}/{DISTRIBUTION_VERSION})"
        )
        self._session = session

    def get_session_for(self, username: str) -> VPNSession:
        """
        Returns the session for the specified user.
        :param username: Proton account username.
        :return:
        """
        self._session = self._proton_sso.get_session(
            account_name=username,
            override_class=VPNSession
        )
        return self._session

    @property
    def session(self) -> VPNSession:
        """Returns the current session object."""
        if not self._session:
            self._session = self._proton_sso.get_default_session(
                override_class=VPNSession
            )

        return self._session

    @staticmethod
    def _get_app_version_header_value(client_type_metadata: ClientTypeMetadata) -> str:
        app_version = f"linux-vpn-{client_type_metadata.type}@{client_type_metadata.version}"

        if client_type_metadata.architecture:
            app_version = f"{app_version}+{client_type_metadata.architecture}"

        return app_version
