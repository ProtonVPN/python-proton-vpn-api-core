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
from proton.vpn.session.servers import LogicalServer
from proton.vpn.session.client_config import ClientConfig
from proton.vpn.core.connection import VPNConnector
from proton.vpn.connection import events, exceptions, states
from unittest.mock import Mock, patch
import pytest


LOGICAL_SERVER_DATA = {
  "Name": "IS#1",
  "ID": "OYB-3pMQQA2Z2Qnp5s5nIvTVO2alU6h82EGLXYHn1mpbsRvE7UfyAHbt0_EilRjxhx9DCAUM9uXfM2ZUFjzPXw==",
  "Status": 1,
  "Servers": [
    {
      "EntryIP": "185.159.158.1",
      "Domain": "node-is-01.protonvpn.net",
      "X25519PublicKey": "yKbYe2XwbeNN9CuPZcwMF/lJp6a62NEGiHCCfpfxrnE=",
      "Status": 1,
    }
  ],
  "Label": "3",
}


def test_get_vpn_server_returns_vpn_server_built_from_logical_server_and_client_config():
    vpn_connector_wrapper = VPNConnector(
      session_holder=None,
      settings_persistence=None,
      usage_reporting=None
    )

    logical_server = LogicalServer(data=LOGICAL_SERVER_DATA)
    client_config = ClientConfig.default()

    vpn_server = vpn_connector_wrapper.get_vpn_server(logical_server, client_config)

    physical_server = logical_server.physical_servers[0]
    assert vpn_server.server_ip == physical_server.entry_ip
    assert vpn_server.domain == physical_server.domain
    assert vpn_server.x25519pk == physical_server.x25519_pk
    assert vpn_server.openvpn_ports.udp == client_config.openvpn_ports.udp
    assert vpn_server.openvpn_ports.tcp == client_config.openvpn_ports.tcp
    assert vpn_server.wireguard_ports.udp == client_config.wireguard_ports.udp
    assert vpn_server.wireguard_ports.tcp == client_config.wireguard_ports.tcp
    assert vpn_server.server_id == logical_server.id
    assert vpn_server.server_name == logical_server.name
    assert vpn_server.label == physical_server.label


@pytest.mark.asyncio
async def test__on_connection_event_swallows_and_does_not_report_policy_errors():
    vpn_connector_wrapper = VPNConnector(
      session_holder=None,
      settings_persistence=None,
      usage_reporting=Mock(),
      state=states.Connected(),
    )

    event = events.Disconnected()
    event.context.error = exceptions.FeaturePolicyError("Policy error")

    await vpn_connector_wrapper._on_connection_event(event)

    vpn_connector_wrapper._usage_reporting.report_error.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [
    exceptions.FeatureError("generic feature error"),
    exceptions.FeatureSyntaxError("Feature syntax error")
])
async def test__on_connection_event_reports_feature_syntax_errors_but_no_other_feature_error(error):
    vpn_connector_wrapper = VPNConnector(
        session_holder=None,
        settings_persistence=None,
        usage_reporting=Mock(),
        state=states.Connected(),
    )

    event = events.Disconnected()
    event.context.error = error

    await vpn_connector_wrapper._on_connection_event(event)
    if isinstance(error, exceptions.FeatureSyntaxError):
        vpn_connector_wrapper._usage_reporting.report_error.assert_called_once_with(event.context.error)
    elif isinstance(error, exceptions.FeatureError):
        vpn_connector_wrapper._usage_reporting.report_error.assert_not_called()
    else:
        raise ValueError(f"Unexpected test parameter: {error}")

@pytest.mark.asyncio
async def test__on_connection_event_reports_unexpected_exceptions_and_bubbles_them_up():
    vpn_connector_wrapper = VPNConnector(
        session_holder=None,
        settings_persistence=None,
        usage_reporting=Mock(),
        state=states.Connected(),
    )

    event = events.Disconnected()
    event.context.error = Exception("Unexpected error")

    with pytest.raises(Exception):
        await vpn_connector_wrapper._on_connection_event(event)

    vpn_connector_wrapper._usage_reporting.report_error.assert_called_once_with(event.context.error)


def test_on_state_change_stores_new_device_ip_when_successfully_connected_to_vpn_and_connection_details_and_device_ip_are_set():
    publisher_mock = Mock()
    session_holder_mock = Mock()
    new_connection_details = events.ConnectionDetails(
        device_ip="192.168.0.1",
        device_country="PT",
        server_ipv4="0.0.0.0",
        server_ipv6=None,
    )
    _ = VPNConnector(
        session_holder=session_holder_mock,
        settings_persistence=None,
        usage_reporting=None,
        connection_persistence=Mock(),
        publisher=publisher_mock
    )

    on_state_change_callback = publisher_mock.register.call_args[0][0]

    connected_event = events.Connected(
        context=events.EventContext(
            connection=Mock(),
            connection_details=new_connection_details
        )
    )
    connected_state = states.Connected(context=states.StateContext(connected_event))

    on_state_change_callback(connected_state)

    vpn_location = session_holder_mock.session.set_location.call_args[0][0]

    session_holder_mock.session.set_location.assert_called_once()
    assert vpn_location.IP == new_connection_details.device_ip


def test_on_state_change_skip_store_new_device_ip_when_successfully_connected_to_vpn_and_connection_details_is_none():
    publisher_mock = Mock()
    session_holder_mock = Mock()
    _ = VPNConnector(
        session_holder=session_holder_mock,
        settings_persistence=None,
        usage_reporting=None,
        connection_persistence=Mock(),
        publisher=publisher_mock
    )

    on_state_change_callback = publisher_mock.register.call_args[0][0]

    connected_event = events.Connected(
        context=events.EventContext(
            connection=Mock(),
            connection_details=None
        )
    )
    connected_state = states.Connected(context=states.StateContext(connected_event))

    on_state_change_callback(connected_state)

    session_holder_mock.session.set_location.assert_not_called()


def test_on_state_change_skip_store_new_device_ip_when_successfully_connected_to_vpn_and_device_ip_is_none():
    publisher_mock = Mock()
    session_holder_mock = Mock()
    new_connection_details = events.ConnectionDetails(
        device_ip=None,
        device_country="PT",
        server_ipv4="0.0.0.0",
        server_ipv6=None,
    )
    _ = VPNConnector(
        session_holder=session_holder_mock,
        settings_persistence=None,
        usage_reporting=None,
        connection_persistence=Mock(),
        publisher=publisher_mock
    )

    on_state_change_callback = publisher_mock.register.call_args[0][0]

    connected_event = events.Connected(
        context=events.EventContext(
            connection=Mock(),
            connection_details=new_connection_details
        )
    )
    connected_state = states.Connected(context=states.StateContext(connected_event))

    on_state_change_callback(connected_state)

    session_holder_mock.session.set_location.assert_not_called()
