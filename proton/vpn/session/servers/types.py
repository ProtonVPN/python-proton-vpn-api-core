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
from __future__ import annotations
import random
from enum import IntFlag
from typing import List, Dict

from proton.vpn.session.exceptions import ServerNotFoundError
from proton.vpn.session.servers.country_codes import get_country_name_by_code


class TierEnum(IntFlag):
    """Contains the tiers used throughout the clients.
        The tier either block or unblock certain features and/or servers/countries.
    """
    FREE = 0
    PLUS = 2
    PM = 3  # "implicit-flag-alias" has been added in 2.17.5, anything lower will throw an error.


class ServerFeatureEnum(IntFlag):
    """
    A Class representing the Server features as encoded in the feature flags field of the API:
    """
    SECURE_CORE = 1 << 0  # 1
    TOR = 1 << 1  # 2
    P2P = 1 << 2  # 4
    STREAMING = 1 << 3  # 8
    IPV6 = 1 << 4  # 16


class PhysicalServer:
    """
    A physical server instance contains the network information
    to initiate a VPN connection to the server.
    """

    def __init__(self, data: Dict):
        self._data = data

    @property
    def id(self) -> str:  # pylint: disable=invalid-name
        """Returns the physical ID of the server."""
        return self._data.get("ID")

    @property
    def entry_ip(self) -> str:
        """Returns the IP of the entered server."""
        return self._data.get("EntryIP")

    @property
    def exit_ip(self) -> str:
        """Returns the IP of the exited server.
            If you want to display to which IP a user is connected
            then use this one.
        """
        return self._data.get("ExitIP")

    @property
    def domain(self) -> str:
        """Returns the Domain of the connected server.
            This is usually used for TLS Authentication.
        """
        return self._data.get("Domain")

    @property
    def enabled(self) -> bool:
        """Returns if the server is enabled or not"""
        return self._data.get("Status") == 1

    @property
    def generation(self) -> str:
        """Returns the generation of the server."""
        return self._data.get("Generation")

    @property
    def label(self) -> str:
        """Returns the label value.
            If label is passed then it ensures that the
            `ExitIP` matches exactly to the server that we're connected.
        """
        return self._data.get("Label")

    @property
    def services_down_reason(self) -> str:
        """Returns the reason of why the servers are down."""
        return self._data.get("ServicesDownReason")

    @property
    def x25519_pk(self) -> str:
        """ X25519 public key of the physical available as a base64 encoded string.
        """
        return self._data.get("X25519PublicKey")

    def __repr__(self):
        if self.label != '':
            return f'PhysicalServer<{self.domain}+b:{self.label}>'

        return f'PhysicalServer<{self.domain}>'


class LogicalServer:  # pylint: disable=too-many-public-methods
    """
    Abstraction of a VPN server.

    One logical servers abstract one or more
    PhysicalServer instances away.
    """

    def __init__(self, data: Dict):
        self._data = data

    def update(self, server_load: ServerLoad):
        """Internally updates the logical server:
            * Load
            * Score
            * Status
        """
        if self.id != server_load.id:
            raise ValueError(
                "The id of the logical server does not match the one of "
                "the server load object"
            )

        self._data["Load"] = server_load.load
        self._data["Score"] = server_load.score
        self._data["Status"] = 1 if server_load.enabled else 0

    @property
    def id(self) -> str:  # pylint: disable=invalid-name
        """Returns the id of the logical server."""
        return self._data.get("ID")

    # Score, load and status can be modified (needed to update loads)
    @property
    def load(self) -> int:
        """Returns the load of the servers.
            This is generally only used for UI purposes.
        """
        return self._data.get("Load")

    @property
    def score(self) -> float:
        """Returns the score of the server.
            The score is automatically calculated by the API and
            is used for the logic of the "Quick Connect".
            The lower the number is the better is for establishing a connection.
        """
        return self._data.get("Score")

    @property
    def enabled(self) -> bool:
        """Returns if the server is enabled or not.
            Usually the API should return 0 if all physical servers
            are not enabled, but just to be sure we also evaluate all
            physical servers.
        """
        return self._data.get("Status") == 1 and any(
            x.enabled for x in self.physical_servers
        )

    # Every other propriety is readonly
    @property
    def name(self) -> str:
        """Name of the logical, ie: CH#10"""
        return self._data.get("Name")

    @property
    def entry_country(self) -> str:
        """2 letter country code entry, ie: CH"""
        return self._data.get("EntryCountry")

    @property
    def entry_country_name(self) -> str:
        """Full name of the entry country (e.g. Switzerland)."""
        return get_country_name_by_code(self.entry_country)

    @property
    def exit_country(self) -> str:
        """2 letter country code exit, ie: CH"""
        return self._data.get("ExitCountry")

    @property
    def exit_country_name(self) -> str:
        """Full name of the exit country (e.g. Argentina)."""
        return get_country_name_by_code(self.exit_country)

    @property
    def host_country(self) -> str:
        """2 letter country code host: CH.
            If there is a host country then it means that this server location
            is emulated, see Smart Routing definition for further clarification.
        """
        return self._data.get("HostCountry")

    @property
    def features(self) -> List[ServerFeatureEnum]:
        """ List of features supported by this Logical."""
        return self.__unpack_bitmap_features(self._data.get("Features", 0))

    def __unpack_bitmap_features(self, server_value):
        server_features = [
            feature_enum
            for feature_enum
            in ServerFeatureEnum
            if (server_value & feature_enum) != 0
        ]
        return server_features

    @property
    def region(self) -> str:
        """Returns the region of the server."""
        return self._data.get("Region")

    @property
    def city(self) -> str:
        """Returns the city of the server."""
        return self._data.get("City")

    @property
    def tier(self) -> int:
        """Returns the minimum required tier to be able to establish a connection.
            Server-side check is always done, so this is mainly for UI purposes.
        """
        return TierEnum(int(self._data.get("Tier")))

    @property
    def latitude(self) -> float:
        """Returns servers latitude."""
        return self._data.get("Location", {}).get("Lat")

    @property
    def longitude(self) -> float:
        """Returns servers longitude."""
        return self._data.get("Location", {}).get("Long")

    @property
    def data(self) -> dict:
        """Returns a copy of the data pertaining this server."""
        return self._data.copy()

    @property
    def physical_servers(self) -> List[PhysicalServer]:
        """ Get all the physicals of supporting a logical
        """
        return [PhysicalServer(x) for x in self._data.get("Servers", [])]

    def get_random_physical_server(self) -> PhysicalServer:
        """ Get a random `enabled` physical linked to this logical
        """
        enabled_servers = [x for x in self.physical_servers if x.enabled]
        if len(enabled_servers) == 0:
            raise ServerNotFoundError("No physical servers could be found")

        return random.choice(enabled_servers)  # nosec B311 # noqa: E501 # pylint: disable=line-too-long # nosemgrep: gitlab.bandit.B311

    def to_dict(self) -> Dict:
        """Converts this object to a dictionary for serialization purposes."""
        return self._data

    def __repr__(self):
        return f'LogicalServer<{self._data.get("Name", "??")}>'


class ServerLoad:
    """Contains data about logical servers to be updated frequently.
    """

    def __init__(self, data: Dict):
        self._data = data

    @property
    def id(self) -> str:  # pylint: disable=invalid-name
        """Returns the id of the logical server."""
        return self._data.get("ID")

    @property
    def load(self) -> int:
        """Returns the load of the servers.
            This is generally only used for UI purposes.
        """
        return self._data.get("Load")

    @property
    def score(self) -> float:
        """Returns the score of the server.
            The score is automatically calculated by the API and
            is used for the logic of the "Quick Connect".
            The lower the number is the better is for establishing a connection.
        """
        return self._data.get("Score")

    @property
    def enabled(self) -> bool:
        """Returns if the server is enabled or not.
        """
        return self._data.get("Status") == 1

    def __str__(self):
        return str(self._data)
