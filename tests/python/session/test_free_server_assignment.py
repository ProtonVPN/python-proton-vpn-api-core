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

from proton.vpn.session.free_server_assignment import FreeServerAssignment


def test_get_returns_none_when_no_assignment_exists():
    assignment = FreeServerAssignment()
    assert assignment.get("US") is None


def test_get_returns_the_id_set_for_the_country():
    assignment = FreeServerAssignment()
    assignment.set("US", "server-1")
    assert assignment.get("US") == "server-1"


def test_set_replaces_a_previous_assignment():
    assignment = FreeServerAssignment()
    assignment.set("US", "server-1")
    assignment.set("US", "server-2")
    assert assignment.get("US") == "server-2"


def test_country_codes_are_case_insensitive():
    assignment = FreeServerAssignment()
    assignment.set("US", "server-1")
    assert assignment.get("us") == "server-1"


def test_clear_discards_every_assignment():
    assignment = FreeServerAssignment()
    assignment.set("US", "server-1")
    assignment.set("JP", "server-2")

    assignment.clear()

    assert assignment.get("US") is None
    assert assignment.get("JP") is None


def test_get_assigned_returns_none_when_no_assignment_exists():
    assignment = FreeServerAssignment()
    candidates = [Mock(id="server-1")]

    assert assignment.get_assigned("US", candidates) is None


def test_get_assigned_returns_the_candidate_matching_the_assignment():
    assignment = FreeServerAssignment()
    assignment.set("US", "server-1")
    matching = Mock(id="server-1")
    candidates = [Mock(id="server-0"), matching]

    assert assignment.get_assigned("US", candidates) is matching


def test_get_assigned_returns_none_when_the_assigned_server_is_not_a_candidate():
    """Covers a server that was removed, disabled, or moved to another tier
    since the assignment was made."""
    assignment = FreeServerAssignment()
    assignment.set("US", "server-1")
    candidates = [Mock(id="server-2")]

    assert assignment.get_assigned("US", candidates) is None
