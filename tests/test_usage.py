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
import pytest
from types import SimpleNamespace

from proton.vpn.core.usage import usage_reporting


@pytest.mark.parametrize("enabled", [True, False])
def test_usage_report_enabled(enabled):
    report_error = SimpleNamespace(invoked=False)

    def capture_exception(error):
        report_error.invoked = True

    usage_reporting.enabled = enabled
    usage_reporting._capture_exception = capture_exception

    EMPTY_ERROR = None
    usage_reporting.report_error(EMPTY_ERROR)

    assert report_error.invoked == enabled, "UsageReporting enable state does not match the error reporting"
