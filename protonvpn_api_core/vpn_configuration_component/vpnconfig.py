from protonvpn_connection.vpnconfig import AbstractVPNConfiguration, AbstractVPNCredentials
PROTON_XDG_CACHE_HOME = os.path.join("~/.home", "protonvpn")


class VPNConnectionCredentials(AbstractVPNCredentials):

    def __init__(self, credentials_component):
        self.credentials_component = credentials_component

    def get_certificate(self) -> str:
        """Get certificate for certificate based authentication"""
        self.credentials_component.get_certificate()

    def get_user_pass(self) -> tuple(str):
        """Get OpenVPN username and password for authentication"""
        self.credentials_component.get_user_pass()


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
        self, server_entry_ip, ports,
        virtual_device_type, custom_dns_list, domain, servername, vpnconnection_credentials):
        self._configfile = None
        self._server_entry_ip = server_entry_ip
        self._ports = ports
        self._virtual_device_type = virtual_device_type
        self._custom_dns_list = custom_dns_list
        self._domain = domain
        self._servername = servername
        self._vpnconnection_credentials = vpnconnection_credentials

    @property
    def servername(self) -> str:
        return self._servername

    @property
    def credentials(self) -> str:
        return self._credentials

    @property
    def protocol(self) -> str:
        raise NotImplementedError()

    @property
    @abstractmethod
    def config_extn(self):
        """Config file extension"""
        pass

    @abstractmethod
    def generate(self):
        pass

    def __enter__(self):
        # We create the configuration file when we enter,
        # and delete it when we exit.
        # This is a race free way of having temporary files.
        if self._configfile is None:
            self.__delete_existing_ovpn_configuration()
            self._configfile = tempfile.NamedTemporaryFile(
                dir=PROTON_XDG_CACHE_HOME, delete=False,
                prefix='ProtonVPN-', suffix=self.config_extn, mode='w'
            )
            self._configfile.write(self.generate())
            self._configfile.close()
            self._configfile_enter_level = 0

        self._configfile_enter_level += 1

        return self._configfile.name

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._configfile is None:
            return

        self._configfile_enter_level -= 1
        if self._configfile_enter_level == 0:
            os.unlink(self._configfile.name)
            self._configfile = None

    def __delete_existing_ovpn_configuration(self):
        for file in os.listdir(PROTON_XDG_CACHE_HOME):
            if file.endswith(".ovpn"):
                os.remove(
                    os.path.join(PROTON_XDG_CACHE_HOME, file)
                )
