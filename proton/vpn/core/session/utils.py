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
import re
from typing import Optional

from proton.vpn import logging

logger = logging.getLogger(__name__)


async def rest_api_request(session, route, **api_request_kwargs):  # noqa: E501 pylint: disable=missing-function-docstring
    logger.info(f"'{route}'", category="api", event="request")
    response = await session.async_api_request(
        route, **api_request_kwargs
    )
    logger.info(f"'{route}'", category="api", event="response")
    return response


def to_semver_build_metadata_format(value: Optional[str]) -> Optional[str]:
    """
    Formats the input value in a format that complies with
    semver's build metadata specs (https://semver.org/#spec-item-10).
    """
    if value is None:
        return None

    value = value.replace("_", "-")
    # Any character not allowed by semver's build metadata suffix
    # specs (https://semver.org/#spec-item-10) is removed.
    value = re.sub(r"[^a-zA-Z0-9\-]", "", value)
    return value
