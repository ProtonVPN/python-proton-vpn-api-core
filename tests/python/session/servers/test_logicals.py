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
import functools
from typing import List

import pytest
from unittest.mock import Mock

from proton.vpn.session.servers import LogicalServer, ServerFeatureEnum
from proton.vpn.session.servers.logicals import (
    sort_servers_alphabetically_by_country_and_server_name,
    sort_servers_by_country_and_location_and_enabled_and_load,
    ServerList
)


def _compact_features(features: List[ServerFeatureEnum]) -> ServerFeatureEnum:
    return functools.reduce(lambda f1, f2: f1 | f2, features, 0)


@pytest.fixture(name="api_response")
def fixture_api_response() -> str:
    return {
        "Code": 1000,
        "LogicalServers": [
            {
                "ID": 1,
                "Name": "JP#10",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Score": 15.0,  # AR#9 has better score (lower is better)
                "Tier": 2,
                "ExitCountry": "JP",
                "City": "Tokyo",
                "Features": ServerFeatureEnum.P2P | ServerFeatureEnum.STREAMING
            },
            {
                "ID": 2,
                "Name": "AR#11",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Score": 1.0,  # Even though it has a better score than CH#9,
                "Tier": 3,     # it's not in the user tier (2).
                "ExitCountry": "AR",
                "City": "Buenos Aires",
                "Features": ServerFeatureEnum.P2P | ServerFeatureEnum.STREAMING
            },
            {
                "ID": 3,
                "Name": "AR#13",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Score": 2.0,  # Even though it has a better score than CH#9,
                "Tier": 3,     # it's not in the user tier (2).
                "ExitCountry": "AR",
                "City": "Rosario",
                "Features": ServerFeatureEnum.P2P | ServerFeatureEnum.STREAMING | ServerFeatureEnum.IPV6
            },
            {
                "ID": 4,
                "Name": "AR#14",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Score": 3.0,  # Even though it has a better score than CH#9,
                "Tier": 3,     # it's not in the user tier (2).
                "ExitCountry": "AR",
                "City": "Rosario",
                "Features": ServerFeatureEnum.P2P | ServerFeatureEnum.IPV6
            },
            {
                "ID": 5,
                "Name": "AR#9",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Score": 10.0,  # Fastest server in the  user tier (2)
                "Tier": 2,
                "ExitCountry": "AR",
                "City": "Rosario"
            },
            {
                "ID": 6,
                "Name": "CH#18-TOR",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Score": 7.0,                       # Even though it has a better score than AR#9,
                "Features": ServerFeatureEnum.TOR,  # TOR servers should be ignored.
                "Tier": 2,
                "ExitCountry": "CH",
                "City": "Wuhan"
            },
            {
                "ID": 7,
                "Name": "CH-US#1",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Score": 8.0,                               # Even though it has a better score than AR#9,
                "Features": ServerFeatureEnum.SECURE_CORE,  # secure core servers should be ignored.
                "Tier": 2,
                "ExitCountry": "CH",
                "City": "Beijing"
            },
            {
                "ID": 8,
                "Name": "JP#1",
                "Score": 9.0,  # Even though it has a better score than AR#9,
                "Status": 0,   # this server is not enabled.
                "Servers": [{"Status": 0}],
                "Tier": 2,
                "ExitCountry": "JP",
                "City": "Osaka",
            },
        ]
    }


def test_server_list_get_fastest(api_response: str):
    server_list = ServerList(
        user_tier=2,
        logicals=[LogicalServer(ls) for ls in api_response["LogicalServers"]]
    )

    fastest = server_list.get_fastest()
    assert fastest.name == "AR#9"


def test_server_list_get_fastest_in_country(api_response: str):
    server_list = ServerList(
        user_tier=3,
        logicals=[LogicalServer(ls) for ls in api_response["LogicalServers"]]
    )

    fastest = server_list.get_fastest_in_country("AR")
    assert fastest.name == "AR#11"


def test_server_list_get_fastest_in_city(api_response: str):
    server_list = ServerList(
        user_tier=3,
        logicals=[LogicalServer(ls) for ls in api_response["LogicalServers"]]
    )

    fastest = server_list.get_fastest_in_city("Rosario")
    assert fastest.name == "AR#13"


def test_server_list_get_available_servers(api_response: str):
    server_list = ServerList(
        user_tier=2,
        logicals=[LogicalServer(ls) for ls in api_response["LogicalServers"]]
    )

    available_servers_generator = \
        ServerList.get_available_servers(server_list.logicals, user_tier=2)

    for server in available_servers_generator:
        assert server.tier <= 2 and server.enabled


@pytest.mark.parametrize("features_requested, features_excluded", [
    (ServerFeatureEnum.P2P, 0),
    (ServerFeatureEnum.IPV6 | ServerFeatureEnum.STREAMING, 0),
    (ServerFeatureEnum.P2P, ServerFeatureEnum.TOR | ServerFeatureEnum.IPV6),
    (0, 0),
    (ServerFeatureEnum.TOR, ServerFeatureEnum.TOR),
])
def test_server_list_get_servers_with_features(
    api_response: str,
    features_requested: ServerFeatureEnum,
    features_excluded: ServerFeatureEnum
):
    server_list = ServerList(
        user_tier=2,
        logicals=[LogicalServer(ls) for ls in api_response["LogicalServers"]]
    )

    servers_with_features_generator = \
        ServerList.get_servers_with_features(
            server_list.logicals,
            features_requested,
            features_excluded
        )

    servers_with_features = list(servers_with_features_generator)

    # test for empty server list when requested and excluded features have an intersection
    if features_requested & features_excluded != 0:
        assert len(servers_with_features) == 0

    for server in servers_with_features:
        assert _compact_features(server.features) & features_excluded == 0 \
            and _compact_features(server.features) & features_requested == features_requested


def test_server_list_get_country_servers(api_response: str):
    server_list = ServerList(
        user_tier=2,
        logicals=[LogicalServer(ls) for ls in api_response["LogicalServers"]]
    )

    country_servers_generator = \
        ServerList.get_servers_in_city(server_list.logicals, "AR")

    for server in country_servers_generator:
        assert server.exit_country == "AR"


def test_server_list_get_city_servers(api_response: str):
    server_list = ServerList(
        user_tier=2,
        logicals=[LogicalServer(ls) for ls in api_response["LogicalServers"]]
    )

    city_servers_generator = \
        ServerList.get_servers_in_country_code(server_list.logicals, "rosario")

    for server in city_servers_generator:
        assert server.city == "rosario"


def test_server_list_get_fastest_server(api_response: str):
    server_list = ServerList(
        user_tier=2,
        logicals=[LogicalServer(ls) for ls in api_response["LogicalServers"]]
    )

    fastest_server = ServerList.get_fastest_server(server_list.logicals)

    assert fastest_server.name == "AR#11"


def test_sort_servers_alphabetically_by_country_and_server_name():
    api_response = {
        "Code": 1000,
        "LogicalServers": [
            {
                "ID": 2,
                "Name": "AR#10",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "ExitCountry": "AR",
            },
            {
                "ID": 1,
                "Name": "JP-FREE#10",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "ExitCountry": "JP",
            },
            {
                "ID": 3,
                "Name": "AR#9",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "ExitCountry": "AR",
            },
            {
                "ID": 5,
                "Name": "Random Name",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "ExitCountry": "JP",
            },
            {
                "ID": 4,
                "Name": "JP#9",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "ExitCountry": "JP",

            },
        ]
    }

    logicals = [LogicalServer(server_dict) for server_dict in api_response["LogicalServers"]]
    logicals.sort(key=sort_servers_alphabetically_by_country_and_server_name)

    expected_server_name_order = ["AR#9", "AR#10", "JP#9", "JP-FREE#10", "Random Name"]
    actual_server_name_order = [server.name for server in logicals]
    assert actual_server_name_order == expected_server_name_order


def test_sort_servers_by_country_and_city_and_enabled_and_load():
    api_response = {
        "Code": 1000,
        "LogicalServers": [
            {
                "ID": 1,
                "Name": "AR#10",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Load": 50,
                "ExitCountry": "AR",
                "City": "Buenos Aires",
            },
            {
                "ID": 2,
                "Name": "AR#9",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Load": 30,  # Lower load, should come before AR#10 in same city
                "ExitCountry": "AR",
                "City": "Buenos Aires",
            },
            {
                "ID": 3,
                "Name": "AR#5",
                "Status": 0,  # Disabled, should come after enabled servers
                "Servers": [{"Status": 0}],
                "Load": 20,
                "ExitCountry": "AR",
                "City": "Buenos Aires",
            },
            {
                "ID": 4,
                "Name": "AR#15",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Load": 20,  # Lowest load in Rosario
                "ExitCountry": "AR",
                "City": "Rosario",
            },
            {
                "ID": 5,
                "Name": "JP#9",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Load": 40,
                "ExitCountry": "JP",
                "City": "Tokyo",
            },
            {
                "ID": 6,
                "Name": "JP#1",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Load": 25,  # Lower load than JP#9
                "ExitCountry": "JP",
                "City": "Tokyo",
            },
            {
                "ID": 7,
                "Name": "JP#10",
                "Status": 0,  # Disabled
                "Servers": [{"Status": 0}],
                "Load": 10,  # Even lower load, but disabled
                "ExitCountry": "JP",
                "City": "Tokyo",
            },
            {
                "ID": 8,
                "Name": "JP#5",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Load": 35,
                "ExitCountry": "JP",
                "City": "Osaka",  # Different city, should come after Tokyo
            },
        ]
    }

    logicals = [LogicalServer(server_dict) for server_dict in api_response["LogicalServers"]]
    logicals.sort(key=sort_servers_by_country_and_location_and_enabled_and_load)

    # Expected order:
    # Enabled servers should come first (True sorts after False, but the function should invert this)
    # 1. Argentina (AR) - Buenos Aires - Enabled first (by load: 30 < 50), then disabled
    #    - AR#9 (enabled, load 30)
    #    - AR#10 (enabled, load 50)
    #    - AR#5 (disabled, load 20)
    # 2. Argentina (AR) - Rosario
    #    - AR#15 (enabled, load 20)
    # 3. Japan (JP) - Osaka
    #    - JP#5 (enabled, load 35)
    # 4. Japan (JP) - Tokyo - Enabled first (by load: 25 < 40), then disabled
    #    - JP#1 (enabled, load 25)
    #    - JP#9 (enabled, load 40)
    #    - JP#10 (disabled, load 10)
    expected_server_name_order = [
        "AR#9",      # Argentina, Buenos Aires, enabled, load 30
        "AR#10",     # Argentina, Buenos Aires, enabled, load 50
        "AR#5",      # Argentina, Buenos Aires, disabled, load 20
        "AR#15",     # Argentina, Rosario, enabled, load 20
        "JP#5",      # Japan, Osaka, enabled, load 35
        "JP#1",      # Japan, Tokyo, enabled, load 25
        "JP#9",      # Japan, Tokyo, enabled, load 40
        "JP#10",     # Japan, Tokyo, disabled, load 10
    ]
    actual_server_name_order = [server.name for server in logicals]
    assert actual_server_name_order == expected_server_name_order
