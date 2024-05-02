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
import os
import pytest
from types import SimpleNamespace
import tempfile
import hashlib

from proton.vpn.core.session_holder import ClientTypeMetadata
from proton.vpn.core.usage import usage_reporting, UsageReporting

SECRET_FILE = "secret.txt"
SECRET_PATH = os.path.join("/home/wozniak/5nkfiudfmk/.cache", SECRET_FILE)
MACHINE_ID = "bg77t2rmpjhgt9zim5gkz4t78jfur39f"
SENTRY_USER_ID = "70cf75689cecae78ec588316320d76477c71031f7fd172dd5577ac95934d4499"
USERNAME = "tester"

@pytest.mark.parametrize("enabled", [True, False])
def test_usage_report_enabled(enabled):
    report_error = SimpleNamespace(invoked=False)

    usage_reporting.init(ClientTypeMetadata("test_usage.py", "none"))

    def capture_exception(error):
        report_error.invoked = True

    usage_reporting.enabled = enabled
    usage_reporting._capture_exception = capture_exception

    EMPTY_ERROR = None
    usage_reporting.report_error(EMPTY_ERROR)

    assert report_error.invoked == enabled, "UsageReporting enable state does not match the error reporting"


@pytest.mark.parametrize("enabled", [True, False])
def test_sanitize_simple_error(enabled):

    error = FileNotFoundError("File not found")
    error.filename = SECRET_PATH

    assert UsageReporting._sanitize_error(error).filename == SECRET_FILE, "Error sanitization failed"


@pytest.mark.parametrize("enabled", [True, False])
def test_sanitize_traceback_error(enabled):

    try:
        open(SECRET_PATH, "r")
    except FileNotFoundError as exception:
        error = (type(exception), exception, exception.__traceback__)

    assert UsageReporting._sanitize_error(error)[1].filename == SECRET_FILE, "Error sanitization failed"


def test_userid_calaculation():
    with tempfile.NamedTemporaryFile() as file:
        file.write(MACHINE_ID.encode('utf-8'))
        file.seek(0)

        assert UsageReporting._get_user_id(
            machine_id_filepath=file.name,
            user_name=USERNAME) == SENTRY_USER_ID, "Error hashing does not match the expected value"
