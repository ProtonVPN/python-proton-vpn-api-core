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
from unittest.mock import Mock, AsyncMock, call

import pytest

from proton.vpn.core.refresher import VPNDataRefresher


@pytest.mark.asyncio
async def test_enable_schedules_all_refreshers_if_the_vpn_session_is_already_loaded():
    session_holder = Mock()
    scheduler = Mock()
    client_config_refresher = Mock()
    client_config_refresher.initial_refresh_delay = 0
    server_list_refresher = Mock()
    server_list_refresher.initial_refresh_delay = 0
    certificate_refresher = Mock()
    certificate_refresher.initial_refresh_delay = 0
    feature_flag_refresher = Mock()
    feature_flag_refresher.initial_refresh_delay = 0
    refresher = VPNDataRefresher(
        session_holder=session_holder,
        scheduler=scheduler,
        client_config_refresher=client_config_refresher,
        server_list_refresher=server_list_refresher,
        certificate_refresher=certificate_refresher,
        feature_flags_refresher=feature_flag_refresher
    )

    session_holder.session.loaded = True

    await refresher.enable()

    assert scheduler.mock_calls == [
        call.run_after(client_config_refresher.initial_refresh_delay, client_config_refresher.refresh),
        call.run_after(server_list_refresher.initial_refresh_delay, server_list_refresher.refresh),
        call.run_after(certificate_refresher.initial_refresh_delay, certificate_refresher.refresh),
        call.run_after(feature_flag_refresher.initial_refresh_delay, feature_flag_refresher.refresh),
        call.start()
    ]

@pytest.mark.asyncio
async def test_enable_fetches_vpn_session_when_not_loaded_and_then_schedules_refreshers():
    session_holder = Mock()
    scheduler = Mock()
    client_config_refresher = Mock()
    client_config_refresher.initial_refresh_delay = 0
    server_list_refresher = Mock()
    server_list_refresher.initial_refresh_delay = 0
    certificate_refresher = Mock()
    certificate_refresher.initial_refresh_delay = 0
    feature_flag_refresher = Mock()
    feature_flag_refresher.initial_refresh_delay = 0

    mock_manager = Mock()
    mock_manager.session_holder = session_holder
    mock_manager.scheduler = scheduler
    mock_manager.client_config_refresher = client_config_refresher
    mock_manager.server_list_refresher = server_list_refresher
    mock_manager.certificate_refresher = certificate_refresher
    mock_manager.feature_flag_refresher = feature_flag_refresher

    refresher = VPNDataRefresher(
        session_holder=session_holder,
        scheduler=scheduler,
        client_config_refresher=client_config_refresher,
        server_list_refresher=server_list_refresher,
        certificate_refresher=certificate_refresher,
        feature_flags_refresher=feature_flag_refresher
    )

    session_holder.session.loaded = False
    session_holder.session.fetch_session_data = AsyncMock()

    await refresher.enable()

    assert mock_manager.mock_calls == [
        call.session_holder.session.fetch_session_data(),
        call.scheduler.run_after(client_config_refresher.initial_refresh_delay, client_config_refresher.refresh),
        call.scheduler.run_after(server_list_refresher.initial_refresh_delay, server_list_refresher.refresh),
        call.scheduler.run_after(certificate_refresher.initial_refresh_delay, certificate_refresher.refresh),
        call.scheduler.run_after(feature_flag_refresher.initial_refresh_delay, feature_flag_refresher.refresh),
        call.scheduler.start()
    ]
