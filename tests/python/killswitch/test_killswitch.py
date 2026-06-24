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

from proton.vpn.killswitch.interface import KillSwitch


def test_instantiation_of_abstract_killswitch_class_fails():
    with pytest.raises(TypeError):
        KillSwitch()


class KillSwitchImpl(KillSwitch):
    async def enable(self, vpn_server=None):
        pass

    async def disable(self):
        pass

    async def enable_ipv6_leak_protection(self):
        pass

    async def disable_ipv6_leak_protection(self):
        pass

    async def _validate(self):
        pass

    async def _get_priority(self):
        return 1


def test_subclass_instantiation_with_required_method_implementations():
    KillSwitchImpl()

