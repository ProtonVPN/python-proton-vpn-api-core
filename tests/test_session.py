import tempfile
from os.path import basename
from unittest.mock import Mock

import pytest

from proton.vpn.core_api.reports import BugReportForm
from proton.vpn.core_api.session import SessionHolder
import time


@pytest.fixture
def apidata():
    return {
        "Code": 1000,
        "OpenVPNConfig": {
            "DefaultPorts": {
                "UDP": [80, 51820, 4569, 1194, 5060],
                "TCP": [443, 7770, 8443]
            }
        },
        "HolesIPs": ["62.112.9.168", "104.245.144.186"],
        "ServerRefreshInterval": 10,
        "FeatureFlags": {
            "NetShield": 0, "GuestHoles": 0, "ServerRefresh": 1,
            "StreamingServicesLogos": 1, "PortForwarding": 0,
            "ModerateNAT": 1, "SafeMode": 0, "StartConnectOnBoot": 1,
            "PollNotificationAPI": 1, "VpnAccelerator": 1,
            "SmartReconnect": 1, "PromoCode": 0, "WireGuardTls": 1
        },
        "CacheExpiration": time.time()
    }


def test_get_client_config_from_api_with_default_cache(apidata):
    apidata["CacheExpiration"] -= 1
    session_mock = Mock()
    cache_handler_mock = Mock()

    cache_handler_mock.load.return_value = None
    session_mock.api_request.return_value = apidata

    s = SessionHolder(session_mock, cache_handler_mock)
    s.get_fresh_client_config()

    cache_handler_mock.load.assert_called_once()
    cache_handler_mock.save.assert_called_once_with(apidata)


def test_get_client_config_from_cache(apidata):
    # Ensure that the cache expires later for test purpose
    cache_handler_mock = Mock()
    apidata["CacheExpiration"] = time.time() + 24 * 60 * 60
    cache_handler_mock.load.return_value = apidata

    s = SessionHolder(Mock(), cache_handler_mock)
    s.get_fresh_client_config()

    cache_handler_mock.load.assert_called_once()


def test_get_client_config_refreshes_cache_when_expired(apidata):
    session_mock = Mock()
    cache_handler_mock = Mock()
    # Ensure that the cache is expired for test purpose
    apidata["CacheExpiration"] = time.time() - 24 * 60 * 60
    cache_handler_mock.load.return_value = apidata
    session_mock.api_request.return_value = apidata

    s = SessionHolder(session_mock, cache_handler_mock)
    s.get_fresh_client_config()

    cache_handler_mock.load.assert_called_once()
    session_mock.api_request.assert_called_once_with(SessionHolder.CLIENT_CONFIG_ENDPOINT)
    cache_handler_mock.save.assert_called_once_with(apidata)


def test_submit_report():
    session_mock = Mock()
    s = SessionHolder(session=session_mock, cache_handler=Mock())

    with tempfile.NamedTemporaryFile(mode="rb") as attachment:
        bug_report = BugReportForm(
            username="test_user",
            email="email@pm.me",
            title="This is a title example",
            description="This is a description example",
            client_version="1.0.0",
            client="Example",
            attachments=[attachment]
        )

        s.submit_bug_report(bug_report)

        session_mock.api_request.assert_called_once()
        api_request_kwargs = session_mock.api_request.call_args.kwargs

        assert api_request_kwargs["endpoint"] == SessionHolder.BUG_REPORT_ENDPOINT

        submitted_data = api_request_kwargs["data"]

        assert len(submitted_data.fields) == 10

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
        assert form_field.name == "Attachment"
        assert form_field.value == bug_report.attachments[0]
        assert form_field.filename == basename(form_field.value.name)
