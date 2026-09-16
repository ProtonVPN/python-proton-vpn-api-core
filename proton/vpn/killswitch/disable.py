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

Turns off the kill switch and IPv6 leak protection of every backend:

    python3 -m proton.vpn.killswitch.disable

For the deb and rpm removal scriptlets, which would otherwise leave a
drop-by-default firewall behind with nothing left able to remove it. Exits
non-zero if anything failed, leaving the caller to decide whether that matters.
"""
from __future__ import annotations

import asyncio
import sys
from typing import Optional, Sequence

from proton.loader import Loader

from proton.vpn.killswitch.interface import KillSwitch


async def disable_all(backends: Optional[Sequence[KillSwitch]] = None) -> int:
    """
    Disables every backend, returning how many of the calls failed.
    """
    if backends is None:
        backends = [component.cls() for component in Loader.get_all("killswitch")]

    failures = 0

    for backend in backends:
        name = type(backend).__name__

        # Attempted independently, so a failure on one still tries the other.
        for what, disable in (
            ("the kill switch", backend.disable),
            ("IPv6 leak protection", backend.disable_ipv6_leak_protection),
        ):
            try:
                await disable()
            except Exception as error:  # noqa pylint: disable=broad-except
                print(f"{name}: could not disable {what}: {error}", file=sys.stderr)
                failures += 1

    return failures


if __name__ == "__main__":
    try:
        sys.exit(1 if asyncio.run(disable_all()) else 0)
    except Exception as unexpected:  # noqa pylint: disable=broad-except
        # Loading the backends is outside the per-call handling above, and a
        # traceback in the middle of apt or dnf output would be alarming.
        print(f"could not disable the kill switches: {unexpected}", file=sys.stderr)
        sys.exit(1)
