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
from dataclasses import dataclass
from typing import List


@dataclass
class VPNServer:
    server_ip: str = None
    openvpn_ports: object = None
    wireguard_ports: object = None
    x25519pk: str = None
    domain: str = None
    servername: str = None


@dataclass
class VPNPubKeyCredentials:
    certificate_pem: str = None
    wg_private_key: str = None
    openvpn_private_key: str = None


@dataclass
class VPNUserPassCredentials:
    username: str = None
    password: str = None


@dataclass
class VPNCredentials:
    pubkey_credentials: VPNPubKeyCredentials = None
    userpass_credentials: VPNUserPassCredentials = None


@dataclass
class Features:
    netshield: int = None
    vpn_accelerator: bool = None
    port_forwarding: bool = None
    random_nat: bool = None
    safe_mode: bool = None


@dataclass
class Settings:
    dns_custom_ips: List[str] = None
    split_tunneling_ips: List[str] = None
    ipv6: bool = None
    features: Features = None
