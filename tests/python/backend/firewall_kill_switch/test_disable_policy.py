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
# Only parses a policy file committed in this repo, never untrusted input.
import xml.etree.ElementTree as ET  # nosemgrep: use-defused-xml
from pathlib import Path

import pytest

POLICY = (
    Path(__file__).parents[4] / "resources" / "me.proton.vpn.kill-switch.disable.policy"
)
ACTION_ID = "me.proton.vpn.kill-switch.disable"
# Where the packaging installs the wrapper.
WRAPPER_PATH = "/usr/libexec/proton-vpn-disable-kill-switch"
WRAPPER = Path(__file__).parents[4] / "resources" / "proton-vpn-disable-kill-switch"


@pytest.fixture(name="action")
def fixture_action():
    root = ET.parse(POLICY).getroot()
    action = root.find(f"action[@id='{ACTION_ID}']")
    assert action is not None, f"{ACTION_ID} missing from {POLICY}"
    return action


@pytest.mark.parametrize("default", ["allow_any", "allow_inactive", "allow_active"])
def test_only_an_admin_may_turn_off_another_users_kill_switch(action, default):
    # "yes" or "auth_self" would let any user remove a kill switch somebody
    # else turned on, which is the vulnerability this policy exists to avoid.
    assert action.findtext(f"defaults/{default}") == "auth_admin"


def test_the_action_covers_the_installed_wrapper(action):
    annotations = {
        annotate.get("key"): annotate.text
        for annotate in action.findall("annotate")
    }

    assert annotations["org.freedesktop.policykit.exec.path"] == WRAPPER_PATH


def test_the_wrapper_runs_isolated_without_caller_arguments():
    # It runs as root: without -I, Python imports from the caller's working
    # directory first, and "$@" would hand caller input to a root process.
    exec_lines = [
        line.strip() for line in WRAPPER.read_text().splitlines()
        if line.strip().startswith("exec ")
    ]

    assert exec_lines == ["exec /usr/bin/python3 -I -m proton.vpn.killswitch.disable"]
