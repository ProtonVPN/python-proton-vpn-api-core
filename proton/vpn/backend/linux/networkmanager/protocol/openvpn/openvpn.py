"""
OpenVPN protocol implementations.


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

from concurrent.futures import Future
import os
import secrets
from getpass import getuser
from ipaddress import IPv4Address, IPv6Address

from jinja2 import Environment, BaseLoader

from gi.repository import NM
import gi
from proton.vpn.backend.linux.networkmanager.core import LinuxNetworkManager
from proton.vpn.connection.vpnconfiguration import VPNConfiguration
from proton.vpn.connection.constants import CA_CERT

gi.require_version("NM", "1.0")

SECRET_PASSWORD = "password"
SECRET_CERT_PASS = "cert-pass"
PASSPHRASE_SECRET_LENGTH = 16
OPENVPN_V2_TEMPLATE = """
# ==============================================================================
# Copyright (c) 2016-2020 Proton Technologies AG (Switzerland)
# Email: contact@protonvpn.com
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR # OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
# ==============================================================================

{%- if enable_ipv6_support %}
push-peer-info
setenv UV_IPV6 1
{%- endif %}

client
dev tun
proto {{ openvpn_protocol|lower }}

{% for ip in serverlist %}
{%- for port in openvpn_ports -%}
remote {{ ip }} {{ port }}
{% endfor %}
{% endfor -%}

remote-random
resolv-retry infinite
nobind
cipher AES-256-GCM
verb 3

tun-mtu 1500
mssfix 0
persist-key
persist-tun

reneg-sec 0

remote-cert-tls server

{%- if not certificate_based %}
auth-user-pass
{%- endif %}

<ca>
{{ca_certificate}}
</ca>

<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
6acef03f62675b4b1bbd03e53b187727
423cea742242106cb2916a8a4c829756
3d22c7e5cef430b1103c6f66eb1fc5b3
75a672f158e2e2e936c3faa48b035a6d
e17beaac23b5f03b10b868d53d03521d
8ba115059da777a60cbfd7b2c9c57472
78a15b8f6e68a3ef7fd583ec9f398c8b
d4735dab40cbd1e3c62a822e97489186
c30a0b48c7c38ea32ceb056d3fa5a710
e10ccc7a0ddb363b08c3d2777a3395e1
0c0b6080f56309192ab5aacd4b45f55d
a61fc77af39bd81a19218a79762c3386
2df55785075f37d8c71dc8a42097ee43
344739a0dd48d03025b0450cf1fb5e8c
aeb893d9a96d1f15519bb3c4dcb40ee3
16672ea16c012664f8a9f11255518deb
-----END OpenVPN Static key V1-----
</tls-crypt>

{%- if certificate_based %}
<cert>
{{cert}}
</cert>
<key>
{{priv_key}}
</key>
{%- endif %}
"""


class OVPNConfig(VPNConfiguration):
    """OpenVPN-specific configuration."""
    PROTOCOL = None
    EXTENSION = ".ovpn"

    def __init__(self, private_key_passphrase, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._private_key_passphrase = private_key_passphrase

    def generate(self) -> str:
        """Method that generates a vpn config file.

        Returns:
            string: configuration file
        """
        openvpn_ports = self._vpnserver.openvpn_ports
        ports = openvpn_ports.tcp if "tcp" == self.PROTOCOL else openvpn_ports.udp

        enable_ipv6_support = self._vpnserver.has_ipv6_support and self._settings.ipv6

        j2_values = {
            "enable_ipv6_support": enable_ipv6_support,
            "openvpn_protocol": self.PROTOCOL,
            "serverlist": [self._vpnserver.server_ip],
            "openvpn_ports": ports,
            "ca_certificate": CA_CERT,
            "certificate_based": self.use_certificate,
        }

        if self.use_certificate:
            j2_values["cert"] =\
                self._vpncredentials.pubkey_credentials.certificate_pem
            password = self._private_key_passphrase.encode()
            j2_values["priv_key"] = self._vpncredentials.pubkey_credentials.\
                get_ed25519_sk_pem(password=password)

        template =\
            (Environment(loader=BaseLoader, autoescape=True)  # noqa: E501 # pylint: disable=line-too-long # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
                .from_string(OPENVPN_V2_TEMPLATE))

        return template.render(j2_values)


class OpenVPNTCPConfig(OVPNConfig):
    """Configuration for OpenVPN using TCP."""
    PROTOCOL = "tcp"


class OpenVPNUDPConfig(OVPNConfig):
    """Configuration for OpenVPN using UDP."""
    PROTOCOL = "udp"


PROTOCOLS = {
    "openvpn-tcp": OpenVPNTCPConfig,
    "openvpn-udp": OpenVPNUDPConfig,
}


class OpenVPN(LinuxNetworkManager):
    """Base class for the backends implementing the OpenVPN protocols."""
    DNS_PRIORITY = -1500
    VIRTUAL_DEVICE_NAME = "proton0"
    connection = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._vpn_settings = None
        self._connection_settings = None

    def setup(self) -> Future:
        """Methods that creates and applies any necessary changes to the connection."""
        passphrase = self._make_passphrase()
        self._generate_connection(passphrase)
        self._modify_connection(passphrase)
        return self.nm_client.add_connection_async(self.connection)

    def _make_passphrase(self):
        return secrets.token_hex(PASSPHRASE_SECRET_LENGTH)

    def _generate_connection(self, private_key_passphrase):
        vpnconfig = PROTOCOLS[self.protocol](
            private_key_passphrase,
            self._vpnserver, self._vpncredentials, self._settings,
            self._use_certificate
        )

        self.connection = self._import_vpn_config(vpnconfig)

        self._unique_id = self.connection.get_uuid()
        self._vpn_settings = self.connection.get_setting_vpn()
        self._connection_settings = self.connection.get_setting_connection()

    def _modify_connection(self, private_key_passphrase):
        """Configure imported vpn connection.
        """
        self._set_custom_connection_id()
        self._set_connection_user_owned()
        self._set_server_certificate_check()
        self._set_dns()
        if self._use_certificate:
            self._set_vpn_cert_credentials(private_key_passphrase)
        else:
            self._set_vpn_credentials()

        self.connection.add_setting(self._connection_settings)

    def _set_custom_connection_id(self):
        self._connection_settings.set_property(NM.SETTING_CONNECTION_ID, self._get_servername())

    def _set_connection_user_owned(self):
        # returns NM.SettingConnection
        # https://lazka.github.io/pgi-docs/NM-1.0/classes/SettingConnection.html#NM.SettingConnection

        self._connection_settings.add_permission(
            NM.SETTING_USER_SETTING_NAME,
            getuser(),
            None
        )

    def _set_server_certificate_check(self):
        appened_domain = "name:" + self._vpnserver.domain
        self._vpn_settings.add_data_item(
            "verify-x509-name", appened_domain
        )

    def _set_dns(self):
        """Apply dns configurations to ProtonVPN connection."""
        # pylint: disable=duplicate-code
        ipv4_config = self.connection.get_setting_ip4_config()
        ipv6_config = self.connection.get_setting_ip6_config()

        self.configure_dns(nm_setting=ipv4_config, ip_version=IPv4Address)

        if self.enable_ipv6_support:
            self.configure_dns(nm_setting=ipv6_config, ip_version=IPv6Address)
        else:
            ipv6_config.set_property(NM.SETTING_IP_CONFIG_DNS_PRIORITY, self.DNS_PRIORITY)
            ipv6_config.set_property(NM.SETTING_IP_CONFIG_IGNORE_AUTO_DNS, True)

        self.connection.add_setting(ipv4_config)
        self.connection.add_setting(ipv6_config)

    def _set_vpn_credentials(self):
        """Add OpenVPN credentials to ProtonVPN connection.

        Args:
            openvpn_username (string): openvpn/ikev2 username
            openvpn_password (string): openvpn/ikev2 password
        """
        # returns NM.SettingVpn if the connection contains one, otherwise None
        # https://lazka.github.io/pgi-docs/NM-1.0/classes/SettingVpn.html
        username, password = self._get_user_pass(True)

        self._vpn_settings.add_data_item(
            "username", username
        )
        # Use System wide password if we are root (No Secret Agent)
        # See https://people.freedesktop.org/~lkundrak/nm-docs/nm-settings.html#secrets-flags
        # => Allow headless testing
        if os.getuid() == 0:
            self._vpn_settings.add_data_item("password-flags", "0")
        self._vpn_settings.add_secret(SECRET_PASSWORD, password)

    def _set_vpn_cert_credentials(self, private_key_passphrase: str):
        """
        Add passphrase to decrypt the private key.
        """
        self._vpn_settings.add_secret(SECRET_CERT_PASS, private_key_passphrase)


class OpenVPNTCP(OpenVPN):
    """Creates a OpenVPNTCP connection."""
    protocol = "openvpn-tcp"
    ui_protocol = "OpenVPN (TCP)"

    @classmethod
    def _get_priority(cls):
        return 1

    @classmethod
    def _validate(cls):
        # FIX ME: This should do a validation to ensure that NM can be used
        return True


class OpenVPNUDP(OpenVPN):
    """Creates a OpenVPNUDP connection."""
    protocol = "openvpn-udp"
    ui_protocol = "OpenVPN (UDP)"

    @classmethod
    def _get_priority(cls):
        return 1

    @classmethod
    def _validate(cls):
        # FIX ME: This should do a validation to ensure that NM can be used
        return True
