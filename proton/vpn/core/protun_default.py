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
from proton.vpn.core.registry import Registry
from proton.vpn.core.settings.settings import DEFAULT_FREE_PROTOCOL
from proton.vpn.session import FeatureFlags
from proton.vpn.session.feature_flags_fetcher import (
    PROTUN_DEFAULT_FOR_FREE_FLAG
)


def is_default_for_free_users(
    registry: Registry, feature_flags: FeatureFlags
) -> bool:
    """Whether protun should be the default protocol for free users."""
    if not feature_flags.get(PROTUN_DEFAULT_FOR_FREE_FLAG):
        return False

    try:
        registry.get(DEFAULT_FREE_PROTOCOL)
    except RuntimeError:
        return False

    return True
