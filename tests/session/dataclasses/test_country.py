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
import pytest
from proton.vpn.session.servers.types import LogicalServer, ServerFeatureEnum, TierEnum
from proton.vpn.session.dataclasses.servers.country import City, Country


COUNTRY_CODE = "AR"
COUNTRY_NAME = "Argentina"
CITIES = ["Buenos Aires", "Rosario"]
ROSARIO_CITY_FEATURES = {
    ServerFeatureEnum.P2P, ServerFeatureEnum.STREAMING, ServerFeatureEnum.IPV6
}


@pytest.fixture()
def servers_raw() -> list[dict]:
    return [
        {
            "ID": 3,
            "Name": "AR#13",
            "Status": 1,
            "Servers": [{"Status": 1}],
            "Score": 2.0,  # Even though it has a better score than CH#9,
            "Tier": 2,     # it's not in the user tier (2).
            "ExitCountry": "AR",
            "City": "Rosario",
            "Features": ServerFeatureEnum.P2P | ServerFeatureEnum.STREAMING | ServerFeatureEnum.IPV6
        },
        {
            "ID": 2,
            "Name": "AR#11",
            "Status": 1,
            "Servers": [{"Status": 1}],
            "Score": 1.0,  # Even though it has a better score than CH#9,
            "Tier": 2,     # it's not in the user tier (2).
            "ExitCountry": "AR",
            "City": "Buenos Aires",
            "Features": ServerFeatureEnum.P2P | ServerFeatureEnum.STREAMING
        },
        {
            "ID": 4,
            "Name": "AR#14",
            "Status": 1,
            "Servers": [{"Status": 1}],
            "Score": 2.0,  # Even though it has a better score than CH#9,
            "Tier": 2,     # it's not in the user tier (2).
            "ExitCountry": "AR",
            "City": "Rosario",
            "Features": ServerFeatureEnum.P2P
        }
    ]


@pytest.fixture()
def non_free_logical_servers(servers_raw) -> list[LogicalServer]:
    return [
        LogicalServer(servers_raw[0]),
        LogicalServer(servers_raw[1]),
        LogicalServer(servers_raw[2])
    ]


@pytest.fixture()
def free_logical_servers(servers_raw) -> list[LogicalServer]:
    servers_raw[0]["Tier"] = 0
    servers_raw[1]["Tier"] = 0
    servers_raw[2]["Tier"] = 0

    return [
        LogicalServer(servers_raw[0]),
        LogicalServer(servers_raw[1]),
        LogicalServer(servers_raw[2])
    ]


@pytest.fixture()
def mixed_free_and_non_logical_servers(servers_raw) -> list[LogicalServer]:
    servers_raw[1]["Tier"] = 0

    return [
        LogicalServer(servers_raw[0]),
        LogicalServer(servers_raw[1]),
        LogicalServer(servers_raw[2])
    ]


class TestCountry:
    def test_name_is_correctly_returned_when_passing_country_code(self):
        country = Country(COUNTRY_CODE, [])
        assert country.name == COUNTRY_NAME

    def test_is_free_returns_true_if_any_free_servers_are_available(self, mixed_free_and_non_logical_servers):
        country_with_some_free_servers = Country(COUNTRY_CODE, mixed_free_and_non_logical_servers)

        assert country_with_some_free_servers.is_free

    def test_cities_are_grouped_and_sorted(self, non_free_logical_servers):
        country = Country(COUNTRY_CODE, non_free_logical_servers)

        cities = country.cities

        assert cities[0].name == CITIES[0]
        assert cities[1].name == CITIES[1]
        assert len(cities) == len(CITIES)


class TestCity:
    def test_features_are_grouped_when_multiple_servers_have_same_features(self, non_free_logical_servers):
        city_name = "Rosario"
        city_servers = [server for server in non_free_logical_servers if server.city == city_name]
        city = City(name=city_name, servers=city_servers)
        assert city.features == ROSARIO_CITY_FEATURES
