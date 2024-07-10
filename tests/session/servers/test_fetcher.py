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

from proton.vpn.session.servers.fetcher import truncate_ip_address


def test_truncate_ip_replaces_last_ip_address_byte_with_a_zero():
    assert truncate_ip_address("1.2.3.4") == "1.2.3.0"


def test_truncate_ip_raises_exception_when_ip_address_is_invalid():
    with pytest.raises(ValueError):
        truncate_ip_address("foobar")
