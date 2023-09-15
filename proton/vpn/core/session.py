"""
Proton VPN Session API.


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
from os.path import basename

import distro

from proton.session import FormData, FormField
from proton.sso import ProtonSSO
from proton.vpn import logging
from proton.vpn.session import VPNSession
from proton.vpn.core.reports import BugReportForm

logger = logging.getLogger(__name__)
DISTRIBUTION = distro.id()
VERSION = distro.version()


@dataclass
class ClientTypeMetadata:  # pylint: disable=missing-class-docstring
    type: str
    version: str


class SessionHolder:
    """Holds the current session object, initializing it lazily when requested."""

    BUG_REPORT_ENDPOINT = "/core/v4/reports/bug"

    def __init__(
        self, client_type_metadata: ClientTypeMetadata,
        session: VPNSession = None
    ):
        self._proton_sso = ProtonSSO(
            appversion=f"linux-vpn-{client_type_metadata.type}@{client_type_metadata.version}",
            user_agent=f"ProtonVPN/{client_type_metadata.version} (Linux; {DISTRIBUTION}/{VERSION})"
        )
        self._session = session

    def get_session_for(self, username: str) -> VPNSession:
        """
        Returns the session for the specified user.
        :param username: Proton account username.
        :return:
        """
        self._session = self._proton_sso.get_session(
            account_name=username,
            override_class=VPNSession
        )
        return self._session

    @property
    def session(self) -> VPNSession:
        """Returns the current session object."""
        if not self._session:
            self._session = self._proton_sso.get_default_session(
                override_class=VPNSession
            )

        return self._session

    def submit_bug_report(self, bug_report: BugReportForm):
        """Submits a bug report to customer support."""
        data = FormData()
        data.add(FormField(name="OS", value=bug_report.os))
        data.add(FormField(name="OSVersion", value=bug_report.os_version))
        data.add(FormField(name="Client", value=bug_report.client))
        data.add(FormField(name="ClientVersion", value=bug_report.client_version))
        data.add(FormField(name="ClientType", value=bug_report.client_type))
        data.add(FormField(name="Title", value=bug_report.title))
        data.add(FormField(name="Description", value=bug_report.description))
        data.add(FormField(name="Username", value=bug_report.username))
        data.add(FormField(name="Email", value=bug_report.email))
        for i, attachment in enumerate(bug_report.attachments):
            data.add(FormField(
                name=f"Attachment-{i}", value=attachment,
                filename=basename(attachment.name)
            ))

        return self._session.api_request(
            endpoint=SessionHolder.BUG_REPORT_ENDPOINT, data=data
        )
