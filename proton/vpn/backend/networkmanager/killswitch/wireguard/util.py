"""
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
# pylint: disable=duplicate-code

from proton.vpn import logging


logger = logging.getLogger(__name__)


def is_ipv6_disabled() -> bool:
    """Returns if IPv6 is disabled at kernel level or not."""
    filepath = "/sys/module/ipv6/parameters/disable"
    try:
        with open(filepath, "r", encoding="utf-8") as ipv6_disabled_file:
            if ipv6_disabled_file.read().strip() != "0":
                return True
    except FileNotFoundError:
        # If flatpak then we don't have access to the file and assume
        # IPv6 is enabled.
        logger.error("Unable to figure if IPv6 is enabled or disabled, probably flatpak install.")
        return False

    return False
