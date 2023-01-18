from proton.vpn.core_api.reports import BugReport, BugReportForm
from proton.session.exceptions import ProtonAPIError, ProtonAPINotReachable
import requests
from unittest.mock import Mock, patch, MagicMock
import tempfile
import pytest
import os


@patch("proton.vpn.core_api.reports.requests.Session.post")
def test_submit_bug_report_successfully_when_provided_with_all_required_fields(post_mock):
    mock_api_response = Mock()
    mock_api_response.status_code = 200
    mock_api_response.headers = {"content-type": "application/json"}
    mock_api_response.json.return_value = {"Code": 1000}
    post_mock.return_value = mock_api_response

    bug_report = BugReport()
    with tempfile.NamedTemporaryFile(mode="rb") as fp: 
        report_form = BugReportForm(
            username="test_user",
            email="email@pm.me",
            title="This is a title example",
            description="This is a description example",
            client_version="1.0.0",
            client="Example",
            attachments=[fp]
        )

        temporary_filename = os.path.basename(report_form.attachments[0].name)

        bug_report.submit(report_form)
        submitted_data = post_mock.call_args[1]["data"]
        submitted_files = post_mock.call_args[1]["files"]

        assert submitted_data["Username"] == report_form.username
        assert submitted_data["Email"] == report_form.email
        assert submitted_data["Title"] == report_form.title
        assert submitted_data["Description"] == report_form.description
        # Assert that the temporary_filename exists in submitted_files
        assert temporary_filename in submitted_files
        # Assert that both file-objects are the same
        assert submitted_files[temporary_filename] == report_form.attachments[0]


@patch("proton.vpn.core_api.reports.requests.Session.post")
def test_submit_bug_report_raises_exception_when_api_returns_error(post_mock):
    mock_api_response = MagicMock()
    mock_api_response.status_code = 100
    mock_api_response.headers = {"content-type": "application/json"}
    mock_api_response.json.return_value = {"Code": 2000, "Error": ""}
    mock_api_response.reason = "Invalid API"
    post_mock.return_value = mock_api_response

    bug_report = BugReport()
    report_form = BugReportForm(
        username="test_user",
        email="email@pm.me",
        title="This is a title example",
        description="This is a description example",
        client_version="1.0.0",
        client="Example",
    )

    with pytest.raises(ProtonAPIError):
        bug_report.submit(report_form)


@patch("proton.vpn.core_api.reports.requests.Session.post")
def test_submit_bug_report_raises_exception_when_api_is_not_reachable(post_mock):
    post_mock.side_effect = requests.RequestException("API Unreachable")

    bug_report = BugReport()
    report_form = BugReportForm(
        username="test_user",
        email="email@pm.me",
        title="This is a title example",
        description="This is a description example",
        client_version="1.0.0",
        client="Example",
    )

    with pytest.raises(ProtonAPINotReachable):
        bug_report.submit(report_form)


