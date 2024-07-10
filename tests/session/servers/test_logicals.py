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
from proton.vpn.session.servers import LogicalServer, ServerFeatureEnum
from proton.vpn.session.servers.logicals import sort_servers_alphabetically_by_country_and_server_name, ServerList


def test_server_list_get_fastest():
    api_response = {
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
            },
            {
                "ID": 2,
                "Name": "AR#11",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Score": 1.0,  # Even though it has a better score than CH#9,
                "Tier": 3,     # it's not in the user tier (2).
                "ExitCountry": "AR",
            },
            {
                "ID": 3,
                "Name": "AR#9",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Score": 10.0,  # Fastest server in the  user tier (2)
                "Tier": 2,
                "ExitCountry": "AR",
            },
            {
                "ID": 4,
                "Name": "CH#18-TOR",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Score": 7.0,                       # Even though it has a better score than AR#9,
                "Features": ServerFeatureEnum.TOR,  # TOR servers should be ignored.
                "Tier": 2,
                "ExitCountry": "CH",
            },
            {
                "ID": 5,
                "Name": "CH-US#1",
                "Status": 1,
                "Servers": [{"Status": 1}],
                "Score": 8.0,                               # Even though it has a better score than AR#9,
                "Features": ServerFeatureEnum.SECURE_CORE,  # secure core servers should be ignored.
                "Tier": 2,
                "ExitCountry": "CH",
            },
            {
                "ID": 6,
                "Name": "JP#1",
                "Score": 9.0,  # Even though it has a better score than AR#9,
                "Status": 0,   # this server is not enabled.
                "Servers": [{"Status": 0}],
                "Tier": 2,
                "ExitCountry": "JP",
            },
        ]
    }

    server_list = ServerList(
        user_tier=2,
        logicals=[LogicalServer(ls) for ls in api_response["LogicalServers"]]
    )

    fastest = server_list.get_fastest()
    assert fastest.name == "AR#9"


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
