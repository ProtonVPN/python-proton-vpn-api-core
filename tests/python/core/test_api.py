"""
Copyright (c) 2026 Proton AG

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
from unittest.mock import Mock

import pytest

from proton.vpn.core.api import ProtonVPNAPI
from proton.vpn.session import FREE_RESCOPE_FLAG
from proton.vpn.session.exceptions import ServerNotFoundError
from proton.vpn.session.free_server_assignment import FreeServerAssignment
from proton.vpn.session.servers.types import LogicalServer, ServerFeatureEnum, TierEnum


def _server(server_id, exit_country="US", tier=TierEnum.FREE, score=1.0, features=0):
    return LogicalServer({
        "ID": server_id,
        "Name": f"{exit_country}#{server_id}",
        "Status": 1,
        "Servers": [{"Status": 1}],
        "Score": score,
        "Tier": int(tier),
        "ExitCountry": exit_country,
        "City": "City",
        "Features": features,
    })


def _api(servers, user_tier, flag_enabled=None):
    api = ProtonVPNAPI.__new__(ProtonVPNAPI)  # skip __init__: no session/registry needed
    api._session_holder = Mock()  # pylint: disable=protected-access
    api._session_holder.user_tier = user_tier  # pylint: disable=protected-access
    session = api._session_holder.session  # pylint: disable=protected-access
    session.server_list = Mock(logicals=servers)
    session.free_server_assignment = FreeServerAssignment()
    if flag_enabled is not None:
        session.feature_flags.get.return_value = flag_enabled
    return api


@pytest.mark.parametrize("user_tier, flag_enabled", [
    (TierEnum.PLUS, True),   # rescope enabled, but paid tier is exempt from it
    (TierEnum.FREE, False),  # free tier, but rescope itself is disabled
], ids=["paid_tier", "free_tier_with_free_rescope_disabled"])
def test_get_server_for_country_gets_the_fastest_server_when_free_rescope_does_not_apply(
    user_tier, flag_enabled
):
    fastest = _server("1", score=1.0)
    slower = _server("2", score=2.0)

    api = _api([slower, fastest], user_tier, flag_enabled=flag_enabled)

    assert api.get_server_for_country("US") is fastest


def test_get_server_for_country_picks_a_candidate_when_free_rescope_is_active_and_unassigned():
    # A single candidate makes the pick deterministic without mocking
    # `random.choice`: whatever it returns must be this server.
    only_candidate = _server("1")
    api = _api([only_candidate], TierEnum.FREE, flag_enabled=True)

    assert api.get_server_for_country("US") is only_candidate


def test_get_server_for_country_reuses_a_valid_assignment_when_free_rescope_is_active():
    assigned = _server("1", score=2.0)
    fastest = _server("2", score=1.0)
    api = _api([fastest, assigned], TierEnum.FREE, flag_enabled=True)
    api._session_holder.session.free_server_assignment.set(  # pylint: disable=protected-access
        "US", assigned.id
    )

    assert api.get_server_for_country("US") is assigned


def test_get_server_for_country_re_picks_when_free_rescope_is_active_and_assignment_is_stale():
    """Covers an assigned server that was removed, disabled, or re-tiered."""
    only_candidate = _server("1")
    api = _api([only_candidate], TierEnum.FREE, flag_enabled=True)
    api._session_holder.session.free_server_assignment.set(  # pylint: disable=protected-access
        "US", "server-that-no-longer-exists"
    )

    assert api.get_server_for_country("US") is only_candidate


def test_get_server_for_country_raises_when_no_server_is_available():
    api = _api([_server("1", exit_country="JP")], TierEnum.FREE, flag_enabled=True)

    with pytest.raises(ServerNotFoundError):
        api.get_server_for_country("US")


def test_get_server_for_country_never_returns_secure_core_or_tor_servers():
    plain = _server("1", score=9.0)
    secure_core = _server("2", score=1.0, features=ServerFeatureEnum.SECURE_CORE)
    tor = _server("3", score=1.0, features=ServerFeatureEnum.TOR)

    api = _api([plain, secure_core, tor], TierEnum.PLUS)

    assert api.get_server_for_country("US") is plain


def test_get_server_for_country_queries_the_free_rescope_flag_by_its_exact_name():
    api = _api([_server("1")], TierEnum.FREE, flag_enabled=False)
    session = api._session_holder.session  # pylint: disable=protected-access

    api.get_server_for_country("US")

    session.feature_flags.get.assert_called_once_with(FREE_RESCOPE_FLAG)
