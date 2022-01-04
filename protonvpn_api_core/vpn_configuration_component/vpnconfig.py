# from protonvpn_connection.vpnconfig import AbstractVPNConfiguration

class AbstractVPNConfiguration:
    pass




class VPNConfiguration(AbstractVPNConfiguration):
    """Provides known methods to VPNConnection.
    
    This class implements the interface declared in VPNConnection. Thus establishes a
    contract on which VPNConnection can act upon and configure any VPN connection type,
    regardless of protocol or implementation.

    The lifespan of this class is short, as it's used only to establisha VPN. If a new
    VPN connection is to be created, a new VPNConfiguration instance must be passed to
    VPNConnection.
    """

    def __init__(
        self, protocol, server_entry_ip, ports,
        virtual_device_type, custom_dns_list, domain, servername, username, password, certificate=None):
        self._protocol = protocol
        self._server_entry_ip = server_entry_ip
        self._ports = ports
        self._virtual_device_type = virtual_device_type
        self._custom_dns_list = custom_dns_list
        self._domain = domain
        self._servername = servername
        self._username = username
        self._password = password
        self._certificate = certificate

    def get_vpn_config_filepath(self, is_certificate=True) -> str:
        """Get filepath to where the config was created."""
        # get template
        # fill template
        # create file on filepath
        return "filepath"

    def get_user_pass(self) -> tuple(str):
        """Get OpenVPN username and password for authentication"""
        return self._username, self._password

    def get_certificate(self) -> str:
        """Get certificate for certificate based authentication"""
        return self._certificate