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
import logging
import tempfile
from os.path import basename
from unittest.mock import AsyncMock, patch, Mock

import pytest
from proton.session.exceptions import ProtonAPINotReachable
from proton.session.transports import TransportFactory

from proton.vpn.session import VPNSession
from proton.vpn.session.session import _client_headers
from proton.vpn.session.dataclasses import BugReportForm
from proton.vpn.session.dataclasses.notifications.nps_survey_response import NPSSurveyResponse

MOCK_ISP = "Proton ISP"
MOCK_COUNTRY = "Middle Earth"
MOCK_TIMEZONE = "Europe/Zurich"


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


# ---------------------------------------------------------------------------
# location translations kept in sync with the server list
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_location_names_stores_and_returns_the_new_translations():
    s = VPNSession()
    translations = Mock()
    s._fetcher = Mock()
    s._fetcher.fetch_location_names = AsyncMock(return_value=translations)

    result = await s.fetch_location_names()

    s._fetcher.fetch_location_names.assert_awaited_once_with()
    assert result is translations
    assert s.location_names is translations




@pytest.mark.asyncio
async def test_fetch_server_list_applies_current_translations_to_new_list():
    s = VPNSession()
    translations = Mock()
    s._location_names = translations
    s._feature_flags = Mock()  # used by the endpoint-version lookup
    new_server_list = Mock()
    s._fetcher = Mock()
    s._fetcher.fetch_server_list = AsyncMock(return_value=new_server_list)

    await s.fetch_server_list()

    new_server_list.set_location_translations.assert_called_once_with(translations)


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


# ---------------------------------------------------------------------------
# x-pm-locale and x-pm-timezone headers
# ---------------------------------------------------------------------------

def test_client_headers_sends_the_locale_as_a_language_tag():
    """The session holds a catalog locale ("fr_FR"), the header wants a tag."""
    assert _client_headers("fr_FR", MOCK_TIMEZONE) == {
        "x-pm-locale": "fr-FR",
        "x-pm-timezone": MOCK_TIMEZONE,
    }


def test_client_headers_omits_the_values_that_could_not_be_resolved():
    assert _client_headers(None, None) == {}


@pytest.fixture
def build_session(mock_transport):
    """Builds a session with an injected locale and timezone, so that these tests
    don't depend on the environment of the machine running them."""
    def build(locale=None, timezone=None):
        session = VPNSession(locale=locale, timezone=timezone)
        session.transport_factory = TransportFactory(lambda _: mock_transport)
        session._vpn_account = create_mock_vpn_account()
        return session
    return build


@pytest.mark.asyncio
async def test_api_request_accepts_the_positional_arguments_of_the_base_session(
    build_session, mock_transport
):
    """The base Session takes jsondata, data and additional_headers positionally,
    so the override must keep accepting them that way."""
    session = build_session(locale="fr_FR", timezone=MOCK_TIMEZONE)

    await session.async_api_request("/foo", None, None, {"x-pm-country": MOCK_COUNTRY})

    additional_headers = mock_transport.async_api_request.call_args.args[3]
    assert additional_headers == {
        "x-pm-country": MOCK_COUNTRY,
        "x-pm-locale": "fr-FR",
        "x-pm-timezone": MOCK_TIMEZONE,
    }


@pytest.mark.asyncio
async def test_api_request_lets_the_caller_win_on_a_conflicting_header(
    build_session, mock_transport
):
    session = build_session(locale="fr_FR", timezone=MOCK_TIMEZONE)

    await session.async_api_request("/foo", None, None, {"x-pm-locale": "de-DE"})

    assert mock_transport.async_api_request.call_args.args[3]["x-pm-locale"] == "de-DE"


@pytest.mark.asyncio
async def test_api_request_omits_the_headers_that_could_not_be_resolved(
    build_session, mock_transport
):
    session = build_session(locale=None, timezone=None)

    await session.submit_nps_response(NPSSurveyResponse())

    additional_headers = mock_transport.async_api_request.call_args.args[3]
    assert "x-pm-locale" not in additional_headers
    assert "x-pm-timezone" not in additional_headers


def test_session_logs_the_headers_once_when_it_is_created(caplog):
    """QA verifies this feature from the client logs. Logged at creation so that
    the auth requests, which never reach async_api_request, are covered too."""
    with caplog.at_level(logging.INFO):
        VPNSession(locale="fr_FR", timezone=MOCK_TIMEZONE)

    assert f"x-pm-locale: fr-FR, x-pm-timezone: {MOCK_TIMEZONE}" in caplog.text


def test_session_logs_the_headers_it_could_not_resolve_as_omitted(caplog):
    with caplog.at_level(logging.INFO):
        VPNSession()

    assert "x-pm-locale: omitted, x-pm-timezone: omitted" in caplog.text


@pytest.mark.asyncio
async def test_api_request_logs_the_endpoint(build_session, caplog):
    session = build_session(locale="fr_FR", timezone=MOCK_TIMEZONE)

    with caplog.at_level(logging.INFO):
        await session.submit_nps_response(NPSSurveyResponse())

    assert VPNSession.NPS_SURVEY_DISMISS_ENDPOINT in caplog.text


@pytest.mark.asyncio
async def test_logout_clears_the_free_server_assignment():
    session = VPNSession()
    session._fetcher = Mock()
    session.free_server_assignment.set("US", "server-1")

    await session.logout()

    assert session.free_server_assignment.get("US") is None


# ---------------------------------------------------------------------------
# The three auth requests that never reach async_api_request
# ---------------------------------------------------------------------------

class RecordingAuthSession(VPNSession):
    """Records the headers the base Session is handed, without reaching a transport.

    The auth requests are made by proton-core below async_api_request, so the
    only thing worth asserting here is what VPNSession passes down to it.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.received_headers = None

    async def async_authenticate(  # pylint: disable=too-many-arguments
            self, username, password, client_secret=None,
            no_condition_check=False, additional_headers=None
    ):
        self.received_headers = additional_headers
        return False

    async def async_validate_2fa_code(self, code, no_condition_check=False,
                                      additional_headers=None):
        self.received_headers = additional_headers
        return False

    async def async_validate_2fa_fido2(self, fido2_assertion, no_condition_check=False,
                                       additional_headers=None):
        self.received_headers = additional_headers
        return False


EXPECTED_AUTH_HEADERS = {"x-pm-locale": "fr-FR", "x-pm-timezone": MOCK_TIMEZONE}


@pytest.fixture
def auth_session():
    session = RecordingAuthSession(locale="fr_FR", timezone=MOCK_TIMEZONE)
    # provide_2fa_fido2 refuses to run without a FIDO2 library, which CI has no
    # reason to install. These tests are about the headers, not about key support.
    session._u2f_keys = Mock()
    return session


@pytest.mark.asyncio
async def test_login_sends_the_client_headers(auth_session):
    await auth_session.login("username", "password")

    assert auth_session.received_headers == EXPECTED_AUTH_HEADERS


@pytest.mark.asyncio
async def test_provide_2fa_code_sends_the_client_headers(auth_session):
    await auth_session.provide_2fa_code("123456")

    assert auth_session.received_headers == EXPECTED_AUTH_HEADERS


@pytest.mark.asyncio
async def test_provide_2fa_fido2_sends_the_client_headers(auth_session):
    await auth_session.provide_2fa_fido2(Mock())

    assert auth_session.received_headers == EXPECTED_AUTH_HEADERS
