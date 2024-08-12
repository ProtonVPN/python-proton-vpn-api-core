"""
Connection persistence.

Connection parameters are persisted to disk so that they can be loaded after a crash.


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
import json
import os
from dataclasses import dataclass
from json import JSONDecodeError
from typing import Optional

from proton.utils.environment import VPNExecutionEnvironment
from proton.vpn import logging

logger = logging.getLogger(__name__)


@dataclass
class ConnectionParameters:
    """Connection parameters to be persisted to disk."""
    connection_id: str
    backend: str
    protocol: str
    server_id: str
    server_name: str
    server_domain: str

    def to_vpn_server(self) -> PersistedVPNServer:
        """Returns the server parameters."""
        return PersistedVPNServer(self)

    def to_settings(self) -> PersistedSettings:
        """Returns the settings parameters."""
        return PersistedSettings()

    def to_credentials(self) -> PersistedCredentials:
        """Returns the credential parameters."""
        return PersistedCredentials()


class ConnectionPersistence:
    """Saves/loads connection parameters to/from disk."""
    FILENAME = "connection_persistence.json"

    def __init__(self, persistence_directory: str = None):
        self._directory = persistence_directory

    @property
    def _connection_file_path(self):
        if not self._directory:
            self._directory = os.path.join(
                VPNExecutionEnvironment().path_cache, "connection"
            )
            os.makedirs(self._directory, mode=0o700, exist_ok=True)

        return os.path.join(self._directory, self.FILENAME)

    def load(self) -> Optional[ConnectionParameters]:
        """Returns the connection parameters loaded from disk, or None if
        no connection parameters were persisted yet."""
        if not os.path.isfile(self._connection_file_path):
            return None

        with open(self._connection_file_path, encoding="utf-8") as file:
            try:
                file_content = json.load(file)
                return ConnectionParameters(
                    connection_id=file_content["connection_id"],
                    backend=file_content["backend"],
                    protocol=file_content["protocol"],
                    server_id=file_content["server_id"],
                    server_name=file_content["server_name"],
                    server_domain=file_content["server_domain"]
                )
            except (JSONDecodeError, KeyError, UnicodeDecodeError):
                logger.exception(
                    "Unexpected error parsing connection persistence file: "
                    f"{self._connection_file_path}",
                    category="CONN", subcategory="PERSISTENCE", event="LOAD"
                )
                return None

    def save(self, connection_parameters: ConnectionParameters):
        """Saves connection parameters to disk."""
        with open(self._connection_file_path, "w", encoding="utf-8") as file:
            json.dump(vars(connection_parameters), file)

    def remove(self):
        """Removes the connection persistence file, if it exists."""
        if os.path.isfile(self._connection_file_path):
            os.remove(self._connection_file_path)
        else:
            logger.warning(
                f"Connection persistence not found when trying "
                f"to remove it: {self._connection_file_path}",
                category="CONN", subcategory="PERSISTENCE", event="REMOVE"
            )


class PersistedVPNServer:
    """Holds the server parameters persisted to disk."""
    # pylint: disable=missing-function-docstring

    def __init__(self, persisted_connection: ConnectionParameters):
        self.server_id = persisted_connection.server_id
        self.server_name = persisted_connection.server_name
        self.domain = persisted_connection.server_domain

    @property
    def x25519pk(self):
        raise RuntimeError("WG public key not available: connection loaded from disk.")

    @property
    def openvpn_ports(self):
        raise RuntimeError("OpenVPN ports not available: connection loaded from disk.")

    @property
    def wireguard_ports(self):
        raise RuntimeError("WireGuard ports not available: connection loaded from disk.")

    @property
    def label(self):
        raise RuntimeError("Label not available: connection loaded from disk.")


class PersistedSettings:
    """Holds the settings parameters persisted to disk."""
    # pylint: disable=missing-function-docstring

    @property
    def dns_custom_ips(self):
        raise RuntimeError("DNS custom IPs not available: connection loaded from disk.")

    @property
    def features(self):
        raise RuntimeError("Features not available: connection loaded from disk.")


class PersistedCredentials:
    """Holds the credentials parameters persisted to disk."""
    # pylint: disable=missing-function-docstring

    @property
    def pubkey_credentials(self):
        raise RuntimeError("Public key credentials not available: connection loaded from disk.")

    @property
    def userpass_credentials(self):
        raise RuntimeError(
            "User/password credentials not available: connection loaded from disk."
        )
