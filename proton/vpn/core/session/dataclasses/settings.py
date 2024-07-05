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
from typing import List
from dataclasses import dataclass
from proton.vpn.core.session.utils import Serializable

# pylint: disable=invalid-name


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
