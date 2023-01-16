"""
Bug Report feature module.
"""

from __future__ import annotations
import os
from json import JSONDecodeError
from dataclasses import dataclass, field
from typing import List
import typing
import distro
import requests

from proton.session.exceptions import ProtonAPIError, ProtonAPINotReachable
from proton.vpn import logging
DISTRIBUTION = distro.id()
VERSION = distro.version()

logger = logging.getLogger(__name__)


@dataclass
class BugReportForm:  # pylint: disable=too-many-instance-attributes,missing-class-docstring, too-few-public-methods
    username: str
    email: str
    title: str
    description: str
    client_version: str
    client: str
    attachments: List[typing.IO, ...] = field(default_factory=list)


class BugReport:  # pylint: disable=too-few-public-methods
    """Create issue reports and submit them to the API."""
    BASE_URL = (
        "https://proton.black/api"
        if os.environ.get("PROTON_API_ENVIRONMENT") == "atlas" else
        "https://api.protonvpn.ch"
    )
    BUG_ROUTE = "/core/v4/reports/bug"

    def __init__(self):
        self._s = requests.Session()
        self._s.headers['x-pm-appversion'] = "linux-vpn@4.0.0"
        self._s.headers['User-Agent'] = f"ProtonVPN/4.0.0 (Linux; {DISTRIBUTION}/{VERSION})"

    def submit(self, report_form: BugReportForm):
        """Submits a report to the API.

        :raises ProtonAPIError: If unable to reach API or the data is not
            properly formatted.
        """
        form_data = self._form_data_to_dict(report_form)
        files = self._form_attachments_to_dict(report_form)

        logger.info(
            f"'{BugReport.BASE_URL+BugReport.BUG_ROUTE}'",
            category="API", event="REQUEST",
        )
        try:
            api_response = self._s.post(
                url=BugReport.BASE_URL + BugReport.BUG_ROUTE,
                data=form_data,
                files=files
            )
        except requests.RequestException as excp:
            raise ProtonAPINotReachable from excp

        logger.info(
            f"'{BugReport.BASE_URL+BugReport.BUG_ROUTE}'",
            category="API", event="RESPONSE",
            optional=f"Status code: {api_response.status_code}; "
            f"Reason: {api_response.reason}; "
        )

        try:
            json_response = api_response.json()
        except (AttributeError, JSONDecodeError):
            json_response = {}

        if api_response.status_code != 200:
            logger.error(
                f"'{BugReport.BUG_ROUTE}'",
                category="API", event="RESPONSE",
                optional=f"Code: {json_response.get('Code')}; "
                f"Error: {json_response.get('Error')}"
            )
            raise ProtonAPIError(
                api_response.status_code,
                api_response.headers,
                json_response
            )

    def _form_data_to_dict(self, report_form: BugReportForm) -> dict:
        return {
            "Country": None,
            "ISP": None,
            "OS": DISTRIBUTION,
            "OSVersion": VERSION,
            "ClientType": "2",  # 1: email;  2: VPN
            "Title": report_form.title,
            "Description": report_form.description,
            "Username": report_form.username,
            "Email": report_form.email,
            "Client": report_form.client,
            "ClientVersion": report_form.client_version,
        }

    def _form_attachments_to_dict(self, report_form: BugReportForm) -> dict:
        files = {}
        for file_object in report_form.attachments:
            file_name = str(os.path.basename(file_object.name))
            files[file_name] = file_object

        return files
