# from protonvpn_connection.vpnconfig import AbstractVPNConfiguration

class AbstractVPNConfiguration:
    pass

class VPNConfiguration(AbstractVPNConfiguration):

    def get_vpn_config_filepath(self) -> str:
        """Get filepath to where the config was created."""
        return "filepath"

    def get_user_pass(self) -> tuple(str):
        """Get OpenVPN username and password for authentication"""
        return "username", "password"

    def get_certificate(self) -> str:
        """Get certificate for certificate based authentication"""
        return "certificate"