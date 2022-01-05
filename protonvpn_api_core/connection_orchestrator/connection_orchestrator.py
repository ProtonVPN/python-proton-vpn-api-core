from protonvpn_api_core.user_settings import DummySettings
from protonvpn_api_core.vpn_configuration_component import VPNConfigurationOpenVPNTCP, VPNConfigurationOpenVPNUDP, VPNConfigurationWireguard
from protonvpn_connection.vpnconnection import VPNConnection
from protonvpn_connection.vpnconfig import AbstractVPNCredentials


class VPNConnectionCredentials(AbstractVPNCredentials):

    def get_certificate(self) -> str:
        """Get certificate for certificate based authentication"""
        return "certificate_filepath"

    def get_user_pass(self) -> tuple:
        """Get OpenVPN username and password for authentication"""
        return "test-user", "test-password"


class DummyPhysicalServer:

    @property
    def server_entry_ip(self):
        return "192.123.1.1"

    @property
    def domain(self):
        return "my.test-domain.com"


class VPNConnector:

    def __init__(self, physical_server, ports, user_settings, credentials, servername=None, protocol=None):
        self._physical_server = physical_server
        self._ports = ports
        self._user_settings = user_settings
        self._credentials = credentials
        self._servername = servername
        self._protocol = protocol

    def connect(self):
        protocol_config = {
            "tcp": VPNConfigurationOpenVPNTCP,
            "udp": VPNConfigurationOpenVPNUDP,
            "wg": VPNConfigurationWireguard
        }

        if self._protocol is None:
            self._protocol = user_settings.protocol.value

        vpnconfig = protocol_config[self._protocol](
            server_entry_ip=self._physical_server.server_entry_ip,
            ports=self._ports,
            vpnconnection_credentials=self._credentials,
            servername=self._servername,
            domain=self._physical_server.domain,
            virtual_device_type="proton0",
            custom_dns_list=self._user_settings.dns_custom_ips if len(self._user_settings.dns_custom_ips) > 0 else None,
            split_tunneling=self._user_settings.split_tunneling if len(self._user_settings.split_tunneling) > 0 else None
        )
        vpnconnection = VPNConnection()
        vpnconnection.up(vpnconfig)

selected_server = "CH#30"
vpnconnector = VPNConnector(DummyPhysicalServer(), [1143], DummySettings(), VPNConnectionCredentials(), selected_server, "tcp")
vpnconnector.connect()