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
from proton.vpn import logging

logger = logging.getLogger(__name__)


async def rest_api_request(session, route, **api_request_kwargs):  # noqa: E501 pylint: disable=missing-function-docstring
    logger.info(f"'{route}'", category="api", event="request")
    response = await session.async_api_request(
        route, **api_request_kwargs
    )
    logger.info(f"'{route}'", category="api", event="response")
    return response
