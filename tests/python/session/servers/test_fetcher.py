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
from unittest.mock import AsyncMock, Mock

import pytest

from proton.vpn.session.servers.server_list_fetcher import (
    EndpointVersion, ServerListFetcher, truncate_ip_address
)


def test_truncate_ip_replaces_last_ip_address_byte_with_a_zero():
    assert truncate_ip_address("1.2.3.4") == "1.2.3.0"


def test_truncate_ip_raises_exception_when_ip_address_is_invalid():
    with pytest.raises(ValueError):
        truncate_ip_address("foobar")


def build_mock_server_list(version, last_modified_time):
    if version is None:
        return None
    sl = Mock()
    sl.version = version
    sl.last_modified_time = last_modified_time
    return sl

CASES = [
    #case_id,serverlist_version,endpoint,expect_v2,expected_modified_since

    # v1 list exists, v2 list requested, expected: ModifiedSince is null
    ("sl_v1_req_v2_mismatch", 1, EndpointVersion.V2, True, None),
    # v2 list exists, v1 list requested, expected: ModifiedSince is null
    ("sl_v2_req_v1_mismatch", 2, EndpointVersion.V1, False, None),
    # v2 list exists, v2 list requested, expected: ModifiedSince is used from serverlist
    ("sl_v2_req_v2_match", 2, EndpointVersion.V2, True, "Wed Aug 12 05:01:26 PM EEST 2026"),
    # v1 list exists, v1 list requested, expected: ModifiedSince is used from serverlist
    ("sl_v1_req_v1_match", 1, EndpointVersion.V1, False, "Wed Aug 12 05:01:26 PM EEST 2026"),
    # no serverlist cached, v1 list requested, expected: ModifiedSince is null
    ("no_sl_req_v1", None, EndpointVersion.V1, False, None),
    # no serverlist cached, v2 list requested, expected: ModifiedSince is null
    ("no_sl_req_v2", None, EndpointVersion.V2, True, None),
]

@pytest.mark.parametrize(
    "case_id,serverlist_version,endpoint,expect_v2,expected_modified_since",
    CASES, ids=[c[0] for c in CASES],
)
@pytest.mark.asyncio
async def test_serverlist_fetch_paths(case_id, serverlist_version, endpoint,
                             expect_v2, expected_modified_since):
    fetcher = ServerListFetcher(
        session=Mock(),
        server_list=build_mock_server_list(serverlist_version,"Wed Aug 12 05:01:26 PM EEST 2026"),
        cache_file=Mock())
    location = Mock()
    fetcher._v2_validate_location = lambda: location
    v1 = AsyncMock(return_value=({}, "last-modified-time"))
    v2 = AsyncMock(return_value=({}, "last-modified-time"))
    fetcher._v1_fetch_logicals = v1
    fetcher._v2_fetch_logicals = v2

    fetcher._cache_and_load_server_list = Mock(return_value=None)

    await fetcher.fetch(endpoint)

    if expect_v2:
        v1.assert_not_awaited()
        v2.assert_awaited_once_with(fetcher._v2_validate_location(), expected_modified_since)
    else:
        v2.assert_not_awaited()
        v1.assert_awaited_once_with(expected_modified_since)

def build_mock_server_list_with_loads(count: int):
    """A server list holding `count` mock logical servers, ready for loads splicing."""
    logicals = []
    for index in range(count):
        logical = Mock()
        logical.id = str(1 + index)
        logical.load = 0
        logical.score = 0.0
        logicals.append(logical)

    server_list = Mock()
    server_list.logicals = logicals
    server_list.to_dict.return_value = {
        "MaxTier": 2,
        "StatusID": "token-123",
        "LogicalServers": [{} for _ in range(count)],
    }
    return server_list, logicals


def _computed_load(load: int, score: float, autoconnectable: bool = True) -> dict:
    return {
        "Load": load, "Score": score,
        "IsEnabled": True, "IsVisible": True,
        "IsAutoconnectable": autoconnectable,
    }


@pytest.mark.asyncio
async def test_v2_update_loads_updates_each_server():
    LOCATION = Mock(Lat=47.3, Long=8.5, Country="CH", IP="1.2.3.4")
    server_list, logicals = build_mock_server_list_with_loads(2)
    fetcher = ServerListFetcher(
        session=Mock(), server_list=server_list, cache_file=Mock()
    )
    fetcher._v2_validate_location = Mock(return_value=LOCATION)
    fetcher._request_status = AsyncMock(return_value=b"binary-status")
    fetcher._compute_loads = Mock(return_value=[
        _computed_load(10, 11.0), _computed_load(20, 22.0)
    ])

    await fetcher.update_loads(EndpointVersion.V2)

    applied = [call.args[0] for call in logicals[0].update.call_args_list + logicals[1].update.call_args_list]
    assert [(load.id, load.score, load.load) for load in applied] == [
        ("1", 11.0, 10), ("2", 22.0, 20),
    ]
