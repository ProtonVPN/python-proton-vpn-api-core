"""
Interfaces required to be able to establish a VPN connection.


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
from typing import List, Optional, Protocol
from dataclasses import dataclass


@dataclass
class ProtocolPorts(Protocol):
    """Dataclass for ports.
    These ports are mainly used for establishing VPN connections.
    """
    udp: List
    tcp: List


class VPNServer(Protocol):  # pylint: disable=too-few-public-methods,R0801
    """
    Contains the necessary data about the server to connect to.

    Some properties like server_id and server_name are not used to establish
    the connection, but they are required for bookkeeping.
    When the connection is retrieved from persistence, then VPN clients
    can use this information to be able to identify the server that
    the VPN connection was established to. The server name is there mainly
    for debugging purposes.

    Attributes:
        server_ip: server ip to connect to.
        domain: domain to be used for x509 verification.
        x25519pk: x25519 public key for wireguard peer verification.
        wireguard_ports: Dict of WireGuard ports, if the protocol requires them.
        openvpn_ports: Dict of OpenVPN ports, if the protocol requires them.
        server_id: ID of the server to connect to.
        server_name: Name of the server to connect to.
    """
    server_ip: str
    openvpn_ports: ProtocolPorts
    wireguard_ports: ProtocolPorts
    domain: str
    x25519pk: str
    server_id: str
    server_name: str
    label: str = None


class VPNPubkeyCredentials(Protocol):  # pylint: disable=too-few-public-methods
    """
    Object that gets certificates and privates keys
    for certificate based connections.

    An instance of this class is to be passed to VPNCredentials.

    Attributes:
        certificate_pem: X509 client certificate in PEM format.
        wg_private_key: wireguard private key in base64 format.
        openvpn_private_key: OpenVPN private key in PEM format.
    """
    certificate_pem: str
    wg_private_key: str
    openvpn_private_key: str


class VPNUserPassCredentials(Protocol):  # pylint: disable=too-few-public-methods
    """Provides username and password for username/password VPN authentication."""
    username: str
    password: str


class VPNCredentials(Protocol):  # pylint: disable=too-few-public-methods
    """
    Credentials are needed to establish a VPN connection.
    Depending on how these credentials are used, one method or the other may be
    irrelevant.

    Limitation:
    You could define only userpass_credentials, though at the cost that you
    won't be able to connect to wireguard (since it's based on certificates)
    and/or openvpn and ikev2 based with certificates. To guarantee maximum
    compatibility, it is recommended to pass both objects for
    username/password and certificates.
    """
    pubkey_credentials: Optional[VPNPubkeyCredentials]
    userpass_credentials: Optional[VPNUserPassCredentials]


class Features(Protocol):
    """
    This class is used to define which features are supported.
    """
    # pylint: disable=too-few-public-methods
    netshield: int
    vpn_accelerator: bool
    port_forwarding: bool
    moderate_nat: bool


class Settings(Protocol):
    """Optional.

    If you would like to pass some specific settings for VPN
    configuration then you should derive from this class and override
    its methods.

    Usage:

    .. code-block::

        from proton.vpn.connection import Settings

        class VPNSettings(Settings):

            @property
            def dns_custom_ips(self):
                return ["192.12.2.1", "175.12.3.5"]

    Note: Not all fields are mandatory to override, only those that are
    actually needed, ie:

    .. code-block::

        from proton.vpn.connection import Settings

        class VPNSettings(Settings):

            @property
            def dns_custom_ips(self):
                return ["192.12.2.1", "175.12.3.5"]

    Passing only this is perfectly fine.
    """
    # pylint: disable=too-few-public-methods
    killswitch: int
    dns_custom_ips: List[str]
    features: Features
    protocol: str
