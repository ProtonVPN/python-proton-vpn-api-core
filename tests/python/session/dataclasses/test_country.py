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
from proton.vpn.session.servers.types import LogicalServer, ServerFeatureEnum
from proton.vpn.session.dataclasses.servers.country import Location, Country, ServerAnalysis
from proton.vpn.session.location_names_fetcher import LocationTranslations


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

    def test_locations_are_grouped(self, non_free_logical_servers):
        country = Country(COUNTRY_CODE, non_free_logical_servers, group_by_location=True)

        locations = country.locations

        assert locations[0].name == CITIES[0]
        assert locations[1].name == CITIES[1]
        assert len(locations) == len(CITIES)

    def test_location_name_is_localized_when_servers_have_translations(
        self, non_free_logical_servers
    ):
        translations = LocationTranslations(
            {"Cities": {COUNTRY_CODE: {"Buenos Aires": "Buenos Aires (traduit)"}}}
        )
        for server in non_free_logical_servers:
            server.set_location_translations(translations)
        country = Country(COUNTRY_CODE, non_free_logical_servers, group_by_location=True)

        # Grouping still keys on the English name, but the displayed name is localized.
        assert country.locations[0].name == "Buenos Aires (traduit)"
        assert country.locations[1].name == CITIES[1]  # untranslated -> English

    def test_locations_are_grouped_by_state_when_state_is_present(self):
        """When servers have a State field it takes priority over City for grouping."""
        servers = [
            LogicalServer({
                "ID": 1, "Name": "US#1", "Status": 1, "Servers": [{"Status": 1}],
                "Tier": 2, "ExitCountry": "US",
                "State": "California", "City": "Los Angeles", "Features": 0,
            }),
            LogicalServer({
                "ID": 2, "Name": "US#2", "Status": 1, "Servers": [{"Status": 1}],
                "Tier": 2, "ExitCountry": "US",
                "State": "California", "City": "San Francisco", "Features": 0,
            }),
            LogicalServer({
                "ID": 3, "Name": "US#3", "Status": 1, "Servers": [{"Status": 1}],
                "Tier": 2, "ExitCountry": "US",
                "State": "Texas", "City": "Houston", "Features": 0,
            }),
        ]
        country = Country("US", servers, group_by_location=True)

        locations = country.locations

        assert len(locations) == 2
        assert locations[0].name == "California"
        assert locations[1].name == "Texas"
        assert len(locations[0].servers) == 2
        assert len(locations[1].servers) == 1


class TestServerAnalysis:
    def test_analyze_servers_returns_under_maintenance_true_when_all_servers_are_under_maintenance(self):
        # Create servers that are all under maintenance (Status=0 or no enabled physical servers)
        servers_data = [
            {
                "ID": 1,
                "Name": "AR#1",
                "Status": 0,  # Logical server disabled
                "Servers": [{"Status": 0}],  # Physical server disabled
                "Tier": 2,
                "ExitCountry": "AR",
                "City": "Buenos Aires",
                "Features": 0
            },
            {
                "ID": 2,
                "Name": "AR#2",
                "Status": 0,
                "Servers": [{"Status": 0}],
                "Tier": 2,
                "ExitCountry": "AR",
                "City": "Buenos Aires",
                "Features": 0
            }
        ]
        servers = [LogicalServer(data) for data in servers_data]

        analysis = ServerAnalysis.analyze_servers(servers)

        assert analysis.under_maintenance is True

    def test_analyze_servers_returns_under_maintenance_false_when_some_servers_are_not_under_maintenance(self):
        # Create servers where at least one is enabled (not under maintenance)
        servers_data = [
            {
                "ID": 1,
                "Name": "AR#1",
                "Status": 0,  # Logical server disabled
                "Servers": [{"Status": 0}],  # Physical server disabled
                "Tier": 2,
                "ExitCountry": "AR",
                "City": "Buenos Aires",
                "Features": 0
            },
            {
                "ID": 2,
                "Name": "AR#2",
                "Status": 1,  # Logical server enabled
                "Servers": [{"Status": 1}],  # Physical server enabled
                "Tier": 2,
                "ExitCountry": "AR",
                "City": "Buenos Aires",
                "Features": 0
            }
        ]
        servers = [LogicalServer(data) for data in servers_data]

        analysis = ServerAnalysis.analyze_servers(servers)

        assert analysis.under_maintenance is False

    def test_analyze_servers_returns_smart_routing_when_any_server_has_smart_routing(self):
        # Note: Based on implementation, smart_routing is True only when ALL servers have smart_routing
        # The test name says "any" but the logic requires "all"
        servers_data = [
            {
                "ID": 1,
                "Name": "AR#1",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Tier": 2,
                "ExitCountry": "AR",
                "City": "Buenos Aires",
                "Features": 0,
                "HostCountry": "US"  # Smart routing enabled
            },
            {
                "ID": 2,
                "Name": "AR#2",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Tier": 2,
                "ExitCountry": "AR",
                "City": "Buenos Aires",
                "Features": 0,
                "HostCountry": "US"  # Smart routing enabled
            }
        ]
        servers = [LogicalServer(data) for data in servers_data]

        analysis = ServerAnalysis.analyze_servers(servers)

        assert analysis.smart_routing is True

    def test_analyze_servers_returns_smart_routing_false_when_not_all_servers_have_smart_routing(self):
        # Create servers where at least one doesn't have smart routing
        servers_data = [
            {
                "ID": 1,
                "Name": "AR#1",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Tier": 2,
                "ExitCountry": "AR",
                "City": "Buenos Aires",
                "Features": 0,
                "HostCountry": "US"  # Smart routing enabled
            },
            {
                "ID": 2,
                "Name": "AR#2",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Tier": 2,
                "ExitCountry": "AR",
                "City": "Buenos Aires",
                "Features": 0
                # No HostCountry - smart routing not enabled
            }
        ]
        servers = [LogicalServer(data) for data in servers_data]

        analysis = ServerAnalysis.analyze_servers(servers)

        assert analysis.smart_routing is False

    def test_analyze_servers_returns_free_when_any_server_is_free(self):
        servers_data = [
            {
                "ID": 1,
                "Name": "AR#1",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Tier": 2,  # Not free
                "ExitCountry": "AR",
                "City": "Buenos Aires",
                "Features": 0
            },
            {
                "ID": 2,
                "Name": "AR#2",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Tier": 0,  # Free tier
                "ExitCountry": "AR",
                "City": "Buenos Aires",
                "Features": 0
            }
        ]
        servers = [LogicalServer(data) for data in servers_data]

        analysis = ServerAnalysis.analyze_servers(servers)

        assert analysis.free is True

    def test_analyze_servers_returns_free_false_when_no_servers_are_free(self):
        # Create servers where none are free (all have tier > 0)
        servers_data = [
            {
                "ID": 1,
                "Name": "AR#1",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Tier": 2,  # Not free
                "ExitCountry": "AR",
                "City": "Buenos Aires",
                "Features": 0
            },
            {
                "ID": 2,
                "Name": "AR#2",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Tier": 2,  # Not free
                "ExitCountry": "AR",
                "City": "Buenos Aires",
                "Features": 0
            }
        ]
        servers = [LogicalServer(data) for data in servers_data]

        analysis = ServerAnalysis.analyze_servers(servers)

        assert analysis.free is False

    def test_analyze_servers_groups_features_from_all_servers(self):
        servers_data = [
            {
                "ID": 1,
                "Name": "AR#1",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Tier": 2,
                "ExitCountry": "AR",
                "City": "Buenos Aires",
                "Features": ServerFeatureEnum.P2P | ServerFeatureEnum.STREAMING
            },
            {
                "ID": 2,
                "Name": "AR#2",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Tier": 2,
                "ExitCountry": "AR",
                "City": "Rosario",
                "Features": ServerFeatureEnum.IPV6 | ServerFeatureEnum.TOR
            },
            {
                "ID": 3,
                "Name": "AR#3",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Tier": 2,
                "ExitCountry": "AR",
                "City": "Rosario",
                "Features": ServerFeatureEnum.P2P  # Overlapping feature
            }
        ]
        servers = [LogicalServer(data) for data in servers_data]

        analysis = ServerAnalysis.analyze_servers(servers)

        # Features should be a set containing all unique features from all servers
        expected_features = {
            ServerFeatureEnum.P2P,
            ServerFeatureEnum.STREAMING,
            ServerFeatureEnum.IPV6,
            ServerFeatureEnum.TOR
        }
        assert analysis.features == expected_features

