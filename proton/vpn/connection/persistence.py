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
from proton.vpn.connection.interfaces import VPNServer

logger = logging.getLogger(__name__)


@dataclass
class ConnectionParameters:
    """Connection parameters to be persisted to disk."""
    connection_id: str
    backend: str
    protocol: str
    server: VPNServer

    @classmethod
    def from_dict(cls, data: dict) -> ConnectionParameters:
        """Creates a ConnectionParameters instance from a dictionary."""
        return cls(
            connection_id=data["connection_id"],
            backend=data["backend"],
            protocol=data["protocol"],
            server=VPNServer.from_dict(data["server"])
        )

    def to_dict(self) -> ConnectionParameters:
        """Creates a dictionary from a ConnectionParameters instance."""
        return {
            "connection_id": self.connection_id,
            "backend": self.backend,
            "protocol": self.protocol,
            "server": self.server.to_dict()
        }


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
                return ConnectionParameters.from_dict(file_content)
            except (JSONDecodeError, KeyError, UnicodeDecodeError):
                logger.warning(
                    "Unexpected error parsing connection persistence file: "
                    f"{self._connection_file_path}",
                    category="CONN", subcategory="PERSISTENCE", event="LOAD",
                    exc_info=True
                )
                return None

    def save(self, connection_parameters: ConnectionParameters):
        """Saves connection parameters to disk."""
        with open(self._connection_file_path, "w", encoding="utf-8") as file:
            json.dump(connection_parameters.to_dict(), file)

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
