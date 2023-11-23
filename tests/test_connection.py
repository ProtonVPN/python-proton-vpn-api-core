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
from unittest.mock import Mock, PropertyMock
from proton.vpn.session.servers import LogicalServer
from proton.vpn.session.client_config import ClientConfig

from proton.vpn.core.connection import VPNConnectorWrapper

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
    vpn_connection_holder = VPNConnectorWrapper(session_holder=None, settings_persistence=None, vpn_connector=None)

    logical_server = LogicalServer(data=LOGICAL_SERVER_DATA)
    client_config = ClientConfig.default()

    vpn_server = vpn_connection_holder.get_vpn_server(logical_server, client_config)

    physical_server = logical_server.physical_servers[0]
    assert vpn_server.server_ip == physical_server.entry_ip
    assert vpn_server.domain == physical_server.domain
    assert vpn_server.x25519pk == physical_server.x25519_pk
    assert vpn_server.udp_ports == client_config.openvpn_ports.udp
    assert vpn_server.tcp_ports == client_config.openvpn_ports.tcp
    assert vpn_server.server_id == logical_server.id
    assert vpn_server.server_name == logical_server.name
    assert vpn_server.label == physical_server.label
