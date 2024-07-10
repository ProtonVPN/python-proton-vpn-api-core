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
from __future__ import annotations
from dataclasses import dataclass
from proton.vpn.session.utils import Serializable

# pylint: disable=invalid-name


@dataclass
class VPNCertificate(Serializable):  # pylint: disable=too-many-instance-attributes
    """ Same object structure coming from the API """
    SerialNumber: str
    ClientKeyFingerprint: str
    ClientKey: str
    """ Client public key used to ask for this certificate in PEM format. """
    Certificate: str
    """ Certificate value in PEM format. Contains the features requested at fetch time"""
    ExpirationTime: int
    RefreshTime: int
    Mode: str
    DeviceName: str
    ServerPublicKeyMode: str
    ServerPublicKey: str

    @staticmethod
    def _deserialize(dict_data: dict) -> VPNCertificate:
        return VPNCertificate(
            SerialNumber=dict_data["SerialNumber"],
            ClientKeyFingerprint=dict_data["ClientKeyFingerprint"],
            ClientKey=dict_data["ClientKey"],
            Certificate=dict_data["Certificate"],
            ExpirationTime=dict_data["ExpirationTime"],
            RefreshTime=dict_data["RefreshTime"],
            Mode=dict_data["Mode"],
            DeviceName=dict_data["DeviceName"],
            ServerPublicKeyMode=dict_data["ServerPublicKeyMode"],
            ServerPublicKey=dict_data["ServerPublicKey"]
        )
