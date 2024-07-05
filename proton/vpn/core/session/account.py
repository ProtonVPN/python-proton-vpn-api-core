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

from typing import Sequence, TYPE_CHECKING

from proton.vpn.core.session.credentials import VPNPubkeyCredentials, VPNSecrets
from proton.vpn.core.session.dataclasses import (
    VPNSettings, VPNLocation, VPNCertificate,
    VPNCredentials, VPNUserPassCredentials
)
from proton.vpn.core.session.exceptions import VPNAccountDecodeError

if TYPE_CHECKING:
    from proton.vpn.core.session.dataclasses import APIVPNSession


class VPNAccount:
    """
    This class is responsible to encapsulate all user vpn account information,
    including credentials (private keys, vpn user and password).
    """

    def __init__(
        self, vpninfo: VPNSettings, certificate: VPNCertificate,
        secrets: VPNSecrets, location: VPNLocation
    ):
        self._vpninfo = vpninfo
        self._certificate = certificate
        self._secrets = secrets
        self._location = location

    @staticmethod
    def from_dict(dict_data: dict) -> VPNAccount:
        """Creates a VPNAccount instance from the specified
            dictionary for deserialization purposes."""
        try:
            return VPNAccount(
                vpninfo=VPNSettings.from_dict(dict_data['vpninfo']),
                certificate=VPNCertificate.from_dict(dict_data['certificate']),
                secrets=VPNSecrets.from_dict(dict_data['secrets']),
                location=VPNLocation.from_dict(dict_data['location'])
            )
        except Exception as exc:
            raise VPNAccountDecodeError("Invalid VPN account") from exc

    def set_certificate(self, new_certificate: VPNCertificate):
        """Set new certificate.
        This affects only when asking for `vpn_credentials` property
        as it's built on the fly.
        """
        self._certificate = new_certificate

    def to_dict(self) -> dict:
        """
        Returns this object as a dictionary for serialization purposes.
        """
        return {
            "vpninfo": self._vpninfo.to_dict(),
            "certificate": self._certificate.to_dict(),
            "secrets": self._secrets.to_dict(),
            "location": self._location.to_dict()
        }

    @property
    def plan_name(self) -> str:
        """
        :return: str `PlanName` value of the account from :class:`api_data.VPNInfo` in
            Non-human readable format.
        """
        return self._vpninfo.VPN.PlanName

    @property
    def plan_title(self) -> str:
        """
        :return: str `PlanName` value of the account from :class:`api_data.VPNInfo`,
            Human readable format, thus if you intend to display the plan
            to the user use this one instead of :class:`VPNAccount.plan_name`.
        """
        return self._vpninfo.VPN.PlanTitle

    @property
    def max_tier(self) -> int:
        """
        :return: int `Maxtier` value of the account from :class:`api_data.VPNInfo`.
        """
        return self._vpninfo.VPN.MaxTier

    @property
    def max_connections(self) -> int:
        """
        :return: int the `MaxConnect` value of the account from :class:`api_data.VPNInfo`.
        """
        return self._vpninfo.VPN.MaxConnect

    @property
    def delinquent(self) -> bool:
        """
        :return: bool if the account is delinquent,
            based the value from :class:`api_data.VPNSettings`.
        """
        return self._vpninfo.Delinquent > 2

    @property
    def active_connections(self) -> Sequence["APIVPNSession"]:
        """
        :return: the list of active VPN session of the authenticated user on the infra.
        """
        raise NotImplementedError

    @property
    def vpn_credentials(self) -> VPNCredentials:
        """ Return :class:`protonvpn.vpnconnection.interfaces.VPNCredentials` to
            provide an interface readily usable to
            instantiate a :class:`protonvpn.vpnconnection.VPNConnection`.
        """
        return VPNCredentials(
            userpass_credentials=VPNUserPassCredentials(
                username=self._vpninfo.VPN.Name,
                password=self._vpninfo.VPN.Password
            ),
            pubkey_credentials=VPNPubkeyCredentials(
                api_certificate=self._certificate,
                secrets=self._secrets,
                strict=True
            )
        )

    @property
    def location(self) -> VPNLocation:
        """
        returns: the physical location the VPN client runs from.
        """
        return self._location
