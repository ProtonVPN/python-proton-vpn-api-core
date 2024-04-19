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
from proton.vpn.core.session.exceptions import ServerNotFoundError
from proton.vpn.core.session.servers.types import PhysicalServer, LogicalServer, ServerLoad
from proton.vpn.core.session.servers.country_codes import get_country_name_by_code

import pytest


ID = "PHYS_SERVER_1"
ENTRY_IP = "192.168.0.1"
EXIT_IP = "192.168.0.2"
DOMAIN = "test.mock-domain.net"
STATUS = 1
GENERATION = 0
LABEL = "TestLabel"
SERVICEDOWNREASON = None
X25519_PK = "UBA8UbeQMmwfFeBp2lwwqwa/aF606BQKjzKHmNoJ03E="

MOCK_PHYSICAL = {
    "ID": ID,
    "EntryIP": ENTRY_IP,
    "ExitIP": EXIT_IP,
    "Domain": DOMAIN,
    "Status": STATUS,
    "Generation": GENERATION,
    "Label": LABEL,
    "ServicesDownReason": SERVICEDOWNREASON,
    "X25519PublicKey": X25519_PK,
}


NAME = "MOCK-SERVER#1"
ENTRYCOUNTRY = "CA"
EXITCOUNTRY = "CA"
TIER = 0
FEATURES = 0
REGION = None
CITY = "Toronto"
SCORE = 2.4273928
HOSTCOUNTRY = None
L_ID = "BzHqSTaqcpjIY9SncE5s7FpjBrPjiGOucCyJmwA6x4nTNqlElfKvCQFr9xUa2KgQxAiHv4oQQmAkcA56s3ZiGQ=="
LAT = 32
LONG = 40
L_STATUS = 1
LOAD = 45


MOCK_LOGICAL = {
    "Name": NAME,
    "EntryCountry": ENTRYCOUNTRY,
    "ExitCountry": EXITCOUNTRY,
    "Domain": DOMAIN,
    "Tier": TIER,
    "Features": FEATURES,
    "Region": REGION,
    "City": CITY,
    "Score": SCORE,
    "HostCountry": HOSTCOUNTRY,
    "ID": L_ID,
    "Location": {
        "Lat": LAT, "Long": LONG
    },
    "Status": L_STATUS,
    "Servers": [MOCK_PHYSICAL],
    "Load": LOAD
}


class TestPhysicalServer:
    def test_init_server(self):
        server = PhysicalServer(MOCK_PHYSICAL)
        assert server.id == ID
        assert server.entry_ip == ENTRY_IP
        assert server.exit_ip == EXIT_IP
        assert server.domain == DOMAIN
        assert server.enabled == STATUS
        assert server.generation == GENERATION
        assert server.label == LABEL
        assert server.services_down_reason == SERVICEDOWNREASON
        assert server.x25519_pk == X25519_PK


class TestLogicalServer:
    def test_init_server(self):
        server = LogicalServer(MOCK_LOGICAL)
        assert server.id == L_ID
        assert server.load == LOAD
        assert server.score == SCORE
        assert server.enabled == L_STATUS
        assert server.name == NAME
        assert server.entry_country == ENTRYCOUNTRY
        assert server.entry_country_name == get_country_name_by_code(server.entry_country)
        assert server.exit_country == EXITCOUNTRY
        assert server.exit_country_name == get_country_name_by_code(server.exit_country)
        assert server.host_country == HOSTCOUNTRY
        assert server.features == []
        assert server.region == REGION
        assert server.city == CITY
        assert server.tier == TIER
        assert server.latitude == LAT
        assert server.longitude == LONG
        assert server.physical_servers[0].domain == PhysicalServer(MOCK_PHYSICAL).domain
        assert server.physical_servers[0].entry_ip == PhysicalServer(MOCK_PHYSICAL).entry_ip
        assert server.physical_servers[0].exit_ip == PhysicalServer(MOCK_PHYSICAL).exit_ip

    def test_update(self):
        server = LogicalServer(MOCK_LOGICAL)

        server_load = ServerLoad({
            "ID": L_ID,
            "Load": 55,
            "Score": 3.14159,
            "enabled": 0
        })
        server.update(server_load)

        assert server.load == 55
        assert server.score == 3.14159
        assert not server.enabled

    def test_get_data(self):
        server = LogicalServer(MOCK_LOGICAL)
        _data = server.data
        _data["Name"] = "test-name"
        assert server.name != _data["Name"]

    def test_get_random_server(self):
        server = LogicalServer(MOCK_LOGICAL)
        _s = server.get_random_physical_server()
        assert _s.x25519_pk == X25519_PK

    def test_get_random_server_raises_exception(self):
        logical_copy = MOCK_LOGICAL.copy()
        logical_copy["Servers"] = []
        server = LogicalServer(logical_copy)

        with pytest.raises(ServerNotFoundError):
            server.get_random_physical_server()
