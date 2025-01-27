"""
This module defines the classes holding the necessary configuration to establish
a VPN connection.


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
import ipaddress
import tempfile
import os

from proton.utils.environment import ExecutionEnvironment


class VPNConfiguration:
    """Base VPN configuration."""
    PROTOCOL = None
    EXTENSION = None

    def __init__(self, vpnserver, vpncredentials, settings,
                 use_certificate=False):
        self._configfile = None
        self._configfile_enter_level = None
        self._vpnserver = vpnserver
        self._vpncredentials = vpncredentials
        self._settings = settings
        self._use_certificate = use_certificate

    def __enter__(self):
        # We create the configuration file when we enter,
        # and delete it when we exit.
        # This is a race free way of having temporary files.

        if self._configfile is None:
            self._delete_existing_configuration()
            # NOTE: we should try to keep filename length
            # below 15 characters, including the prefix.
            self._configfile = tempfile.NamedTemporaryFile(
                dir=self.__base_path, delete=False,
                prefix='pvpn', suffix=self.EXTENSION, mode='w'
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

    def _delete_existing_configuration(self):
        for file in self.__base_path:
            if file.endswith(f".{self.EXTENSION}"):
                os.remove(os.path.join(self.__base_path, file))

    def generate(self) -> str:
        """
        Generates the configuration file content.
        """
        raise NotImplementedError

    @property
    def use_certificate(self):
        """
        Returns True if the configuration uses a certificate, and False
        otherwise.
        """
        return self._use_certificate

    @property
    def __base_path(self):
        return ExecutionEnvironment().path_runtime

    @staticmethod
    def cidr_to_netmask(cidr) -> str:
        """Returns the subnet netmask from the CIDR."""
        subnet = ipaddress.IPv4Network(f"0.0.0.0/{cidr}")
        return str(subnet.netmask)

    @staticmethod
    def is_valid_ipv4(ip_address) -> bool:
        """Returns True if the specified ip address is a valid IPv4 address,
        and False otherwise."""
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            return False

        return True
