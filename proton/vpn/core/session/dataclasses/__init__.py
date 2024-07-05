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

from proton.vpn.core.session.dataclasses.bug_report import BugReportForm
from proton.vpn.core.session.dataclasses.certificate import VPNCertificate
from proton.vpn.core.session.dataclasses.credentials import (
    VPNUserPassCredentials, VPNCredentials
)
from proton.vpn.core.session.dataclasses.location import VPNLocation
from proton.vpn.core.session.dataclasses.login_result import LoginResult
from proton.vpn.core.session.dataclasses.sessions import APIVPNSession, VPNSessions
from proton.vpn.core.session.dataclasses.settings import VPNInfo, VPNSettings

__all__ = [
    "BugReportForm",
    "VPNCertificate",
    "VPNUserPassCredentials", "VPNCredentials",
    "VPNLocation",
    "LoginResult",
    "APIVPNSession", "VPNSessions",
    "VPNInfo", "VPNSettings"
]
