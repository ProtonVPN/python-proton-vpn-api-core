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
import tempfile
from os.path import basename
from unittest.mock import AsyncMock, patch, Mock

import pytest
from proton.session.transports import TransportFactory

from proton.vpn.session import VPNSession
from proton.vpn.session.dataclasses import BugReportForm
from proton.vpn.session.dataclasses.notifications.nps_survey_response import NPSSurveyResponse

MOCK_ISP = "Proton ISP"
MOCK_COUNTRY = "Middle Earth"


def create_mock_vpn_account():
    vpn_account = Mock
    vpn_account.location = Mock()
    vpn_account.location.ISP = MOCK_ISP
    vpn_account.location.Country = MOCK_COUNTRY
    return vpn_account


@pytest.mark.asyncio
async def test_submit_report():
    s = VPNSession()
    s._vpn_account = create_mock_vpn_account()
    attachments = []

    with tempfile.NamedTemporaryFile(mode="rb") as attachment1, tempfile.NamedTemporaryFile(mode="rb") as attachment2:
        attachments.append(attachment1)
        attachments.append(attachment2)

        bug_report = BugReportForm(
            username="test_user",
            email="email@pm.me",
            title="This is a title example",
            description="This is a description example",
            client_version="1.0.0",
            client="Example",
            attachments=attachments
        )

        with patch.object(s, "async_api_request") as patched_async_api_request:
            await s.submit_bug_report(bug_report)

            patched_async_api_request.assert_called_once()
            api_request_kwargs = patched_async_api_request.call_args.kwargs

        assert api_request_kwargs["endpoint"] == s.BUG_REPORT_ENDPOINT

        submitted_data = api_request_kwargs["data"]

        assert len(submitted_data.fields) == 13

        form_field = submitted_data.fields[0]
        assert form_field.name == "OS"
        assert form_field.value == bug_report.os

        form_field = submitted_data.fields[1]
        assert form_field.name == "OSVersion"
        assert form_field.value == bug_report.os_version

        form_field = submitted_data.fields[2]
        assert form_field.name == "Client"
        assert form_field.value == bug_report.client

        form_field = submitted_data.fields[3]
        assert form_field.name == "ClientVersion"
        assert form_field.value == bug_report.client_version

        form_field = submitted_data.fields[4]
        assert form_field.name == "ClientType"
        assert form_field.value == bug_report.client_type

        form_field = submitted_data.fields[5]
        assert form_field.name == "Title"
        assert form_field.value == bug_report.title

        form_field = submitted_data.fields[6]
        assert form_field.name == "Description"
        assert form_field.value == bug_report.description

        form_field = submitted_data.fields[7]
        assert form_field.name == "Username"
        assert form_field.value == bug_report.username

        form_field = submitted_data.fields[8]
        assert form_field.name == "Email"
        assert form_field.value == bug_report.email

        form_field = submitted_data.fields[9]
        assert form_field.name == "ISP"
        assert form_field.value == MOCK_ISP

        form_field = submitted_data.fields[10]
        assert form_field.name == "Country"
        assert form_field.value == MOCK_COUNTRY

        form_field = submitted_data.fields[11]
        assert form_field.name == "Attachment-0"
        assert form_field.value == bug_report.attachments[0]
        assert form_field.filename == basename(form_field.value.name)

        form_field = submitted_data.fields[12]
        assert form_field.name == "Attachment-1"
        assert form_field.value == bug_report.attachments[1]
        assert form_field.filename == basename(form_field.value.name)


# ---------------------------------------------------------------------------
# submit_nps_response
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_transport():
    transport = Mock()
    transport.async_api_request = AsyncMock(return_value={"Code": 1000})
    return transport


@pytest.fixture
def nps_session(mock_transport):
    s = VPNSession()
    s.transport_factory = TransportFactory(lambda _: mock_transport)
    s._vpn_account = create_mock_vpn_account()
    return s


@pytest.mark.asyncio
async def test_submit_nps_response_submit_uses_submit_endpoint(nps_session, mock_transport):
    response = NPSSurveyResponse(
        user_score=9,
        user_comments="Great service",
        response_type=NPSSurveyResponse.ResponseType.SUBMIT,
    )
    await nps_session.submit_nps_response(response)

    endpoint = mock_transport.async_api_request.call_args.args[0]
    assert endpoint == VPNSession.NPS_SURVEY_SUBMIT_ENDPOINT


@pytest.mark.asyncio
async def test_submit_nps_response_submit_sends_score_and_comment(nps_session, mock_transport):
    response = NPSSurveyResponse(
        user_score=8,
        user_comments="Very good",
        response_type=NPSSurveyResponse.ResponseType.SUBMIT,
    )
    await nps_session.submit_nps_response(response)

    jsondata = mock_transport.async_api_request.call_args.args[1]
    assert jsondata["Score"] == 8
    assert jsondata["Comment"] == "Very good"


@pytest.mark.asyncio
async def test_submit_nps_response_dismiss_uses_dismiss_endpoint(nps_session, mock_transport):
    response = NPSSurveyResponse(user_score=0, user_comments="")
    await nps_session.submit_nps_response(response)

    endpoint = mock_transport.async_api_request.call_args.args[0]
    assert endpoint == VPNSession.NPS_SURVEY_DISMISS_ENDPOINT


@pytest.mark.asyncio
async def test_submit_nps_response_dismiss_sends_empty_data(nps_session, mock_transport):
    response = NPSSurveyResponse(user_score=0, user_comments="")
    await nps_session.submit_nps_response(response)

    jsondata = mock_transport.async_api_request.call_args.args[1]
    assert jsondata == {}


@pytest.mark.asyncio
async def test_submit_nps_response_includes_country_header(nps_session, mock_transport):
    response = NPSSurveyResponse(user_score=5, user_comments="OK")
    await nps_session.submit_nps_response(response)

    additional_headers = mock_transport.async_api_request.call_args.args[3]
    assert additional_headers["x-pm-country"] == MOCK_COUNTRY


@pytest.mark.asyncio
async def test_submit_nps_response_uses_post_method(nps_session, mock_transport):
    response = NPSSurveyResponse()
    await nps_session.submit_nps_response(response)

    method = mock_transport.async_api_request.call_args.args[4]
    assert method == "post"

