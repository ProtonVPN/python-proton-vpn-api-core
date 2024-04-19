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

import os as sys_os
import typing
from typing import List
import json
from dataclasses import dataclass, asdict, field

import distro


# pylint: disable=invalid-name


@dataclass
class LoginResult:  # pylint: disable=missing-class-docstring
    success: bool
    authenticated: bool
    twofa_required: bool


class Serializable:  # pylint: disable=missing-class-docstring
    def to_json(self) -> str:  # pylint: disable=missing-function-docstring
        return json.dumps(asdict(self))

    def to_dict(self) -> dict:  # pylint: disable=missing-function-docstring
        return asdict(self)

    @classmethod
    def from_dict(cls, dict_data: dict) -> 'Serializable':  # noqa: E501 pylint: disable=missing-function-docstring
        return cls._deserialize(dict_data)

    @classmethod
    def from_json(cls, data: str) -> 'Serializable':  # pylint: disable=missing-function-docstring
        dict_data = json.loads(data)
        return cls._deserialize(dict_data)

    @staticmethod
    def _deserialize(dict_data: dict) -> 'Serializable':
        raise NotImplementedError


@dataclass
class VPNInfo(Serializable):  # pylint: disable=too-many-instance-attributes
    """ Same object structure as the one coming from the API"""
    ExpirationTime: int
    Name: str
    Password: str
    GroupID: str
    Status: int
    PlanName: str
    PlanTitle: str
    MaxTier: int
    """ Maximum tier value that this account can vpn connect to """
    MaxConnect: int
    """ Maximum number of simultaneous session on the infrastructure"""
    Groups: List[str]
    """ List of groups that this account belongs to """
    NeedConnectionAllocation: bool

    @staticmethod
    def _deserialize(dict_data: dict) -> VPNInfo:
        return VPNInfo(
            ExpirationTime=dict_data["ExpirationTime"],
            Name=dict_data["Name"],
            Password=dict_data["Password"],
            GroupID=dict_data["GroupID"],
            Status=dict_data["Status"],
            PlanName=dict_data["PlanName"],
            PlanTitle=dict_data["PlanTitle"],
            MaxTier=dict_data["MaxTier"],
            MaxConnect=dict_data["MaxConnect"],
            Groups=dict_data["Groups"],
            NeedConnectionAllocation=dict_data["NeedConnectionAllocation"]
        )


@dataclass
class VPNSettings(Serializable):  # pylint: disable=too-many-instance-attributes
    """ Same object structure as the one coming from the API"""
    VPN: VPNInfo
    Services: int
    Subscribed: int
    Delinquent: int
    """ Encode the deliquent status of the account """
    HasPaymentMethod: int
    Credit: int
    Currency: str
    Warnings: List[str]

    @staticmethod
    def _deserialize(dict_data: dict) -> VPNSettings:
        return VPNSettings(
            VPN=VPNInfo.from_dict(dict_data["VPN"]),
            Services=dict_data["Services"],
            Subscribed=dict_data["Subscribed"],
            Delinquent=dict_data["Delinquent"],
            HasPaymentMethod=dict_data["HasPaymentMethod"],
            Credit=dict_data["Credit"],
            Currency=dict_data["Currency"],
            Warnings=dict_data["Warnings"]
        )


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


@dataclass
class APIVPNSession(Serializable):  # pylint: disable=missing-class-docstring
    SessionID: str
    ExitIP: str
    Protocol: str

    @staticmethod
    def _deserialize(dict_data: dict) -> APIVPNSession:
        return APIVPNSession(
            SessionID=dict_data["SessionID"],
            ExitIP=dict_data["ExitIP"],
            Protocol=dict_data["Protocol"]
        )


@dataclass
class VPNSessions(Serializable):
    """ The list of active VPN session of an account on the infra """
    Sessions: List[APIVPNSession]

    def __len__(self):
        return len(self.Sessions)

    @staticmethod
    def _deserialize(dict_data: dict) -> VPNSessions:
        session_list = [APIVPNSession.from_dict(value) for value in dict_data['Sessions']]
        return VPNSessions(Sessions=session_list)


@dataclass
class VPNLocation(Serializable):
    """Data about the physical location the VPN client runs from."""
    IP: str
    Lat: float
    Long: float
    Country: str
    ISP: str

    @staticmethod
    def _deserialize(dict_data: dict) -> VPNLocation:
        """
        Builds a Location object from a dict containing the parsed
        JSON response returned by the API.
        """
        return VPNLocation(
            IP=dict_data["IP"],
            Lat=dict_data["Lat"],
            Long=dict_data["Long"],
            Country=dict_data["Country"],
            ISP=dict_data["ISP"]
        )


VPN_CLIENT_TYPE = "2"  # 1: email;  2: VPN


def get_desktop_environment():
    """Returns the current desktop environment"""
    return sys_os.environ.get('XDG_CURRENT_DESKTOP', "Unknown DE")


def get_distro_variant():
    """Returns the current distro environment"""
    distro_variant = distro.os_release_attr('variant')
    return f"; {distro_variant}" if distro_variant else ""


def generate_os_string():
    """Returns a string which contains information such as the distro, desktop environment
    and distro variant if it exists"""
    return f"{distro.id()} ({get_desktop_environment()}{get_distro_variant()})"


@dataclass
class BugReportForm:  # pylint: disable=too-many-instance-attributes
    """Bug report form data to be submitted to customer support."""
    username: str
    email: str
    title: str
    description: str
    client_version: str
    client: str
    attachments: List[typing.IO] = field(default_factory=list)
    os: str = generate_os_string()  # pylint: disable=invalid-name
    os_version: str = distro.version()
    client_type: str = VPN_CLIENT_TYPE
