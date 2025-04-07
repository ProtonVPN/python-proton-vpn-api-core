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
from unittest.mock import Mock, AsyncMock

import pytest

from proton.vpn.core.refresher.certificate_refresher import CertificateRefresher, generate_backoff_value
from proton.vpn.core.refresher.scheduler import RunAgain
from proton.session.exceptions import ProtonAPIError


@pytest.mark.asyncio
async def test_refresh_schedules_next_refresh_if_certificate_is_expired_and_api_error_exception_is_raised():
    session_holder = Mock()
    session = session_holder.session

    refresher = CertificateRefresher(session_holder=session_holder)

    session.fetch_certificate = AsyncMock(side_effect=ProtonAPIError(
        http_code=429,
        http_headers={},
        json_data={"Code": 429, "Error": "Error message"}
    ))
    new_certificate = Mock()
    new_certificate.remaining_time_to_next_refresh = 600

    next_refresh_delay = await refresher.refresh()


@pytest.mark.asyncio
async def test_refresh_fetches_certificate_if_expired_and_returns_next_refresh_delay():
    session_holder = Mock()
    session = session_holder.session

    refresher = CertificateRefresher(session_holder=session_holder)

    session.fetch_certificate = AsyncMock()
    new_certificate = Mock()
    new_certificate.remaining_time_to_next_refresh = 600
    session.fetch_certificate.return_value= new_certificate

    next_refresh_delay = await refresher.refresh()

    assert next_refresh_delay == RunAgain.after_seconds(new_certificate.remaining_time_to_next_refresh)


@pytest.mark.parametrize("nth_failed_attempt, expected_backoff", [
    (0, 1),
    (1, 2),
    (2, 4),
    (3, 8),
    (4, 16),
    (5, 32)
])
def test_generate_backoff_value_generates_expected_value(nth_failed_attempt, expected_backoff):
    backoff_in_seconds = 1
    random_component = 1

    backoff = generate_backoff_value(
        number_of_failed_refresh_attempts=nth_failed_attempt,
        backoff_in_seconds=backoff_in_seconds,
        random_component=random_component
    )

    assert backoff == expected_backoff
