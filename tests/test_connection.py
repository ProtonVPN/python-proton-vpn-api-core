from proton.vpn.servers.server_types import LogicalServer

from proton.vpn.core_api.client_config import ClientConfig
from proton.vpn.core_api.connection import VPNConnectorWrapper

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
}


def test_get_vpn_server_returns_vpn_server_built_from_logical_server_and_client_config():
    vpn_connection_holder = VPNConnectorWrapper(session_holder=None, settings=None)

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
