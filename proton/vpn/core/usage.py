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
import sentry_sdk
from sentry_sdk.integrations.dedupe import DedupeIntegration
from sentry_sdk.integrations.stdlib import StdlibIntegration
from sentry_sdk.integrations.modules import ModulesIntegration

from proton.vpn.core.session_holder import ClientTypeMetadata, DISTRIBUTION_VERSION, DISTRIBUTION_ID
from proton.vpn.core.session.dataclasses import get_desktop_environment

DSN = "https://9a5ea555a4dc48dbbb4cfa72bdbd0899@vpn-api.proton.me/core/v4/reports/sentry/25"


class UsageReporting:
    """Sends anonymous usage reports to Proton."""

    def __init__(self):
        self.enabled = False
        self._capture_exception = None

    def init(self, client_type_metadata: ClientTypeMetadata, enabled: bool):
        """This method should be called before reporting, otherwise reports will be ignored."""

        sentry_sdk.init(
            dsn=DSN,
            release=f"{client_type_metadata.type}-{client_type_metadata.version}",
            server_name=False,           # Don't send the computer name
            default_integrations=False,  # We want to be explicit about the integrations we use
            integrations=[
                DedupeIntegration(),     # Yes we want to avoid event duplication
                StdlibIntegration(),     # Yes we want info from the standard lib objects
                ModulesIntegration()     # Yes we want to know what python modules are installed
            ]
        )

        # Using configure_scope to set a tag works with older versions of
        # sentry (0.12.2) and so works on ubuntu 20.
        with sentry_sdk.configure_scope() as scope:
            scope.set_tag("distro_name", DISTRIBUTION_ID)
            scope.set_tag("distro_version", DISTRIBUTION_VERSION)
            scope.set_tag("desktop_environment", get_desktop_environment())

        self.enabled = enabled

        # Store _capture_exception as a member, so it's easier to test.
        self._capture_exception = sentry_sdk.capture_exception

    def disable(self):
        """Disables anonymous usage reporting. """
        self.enabled = False

    def enable(self):
        """Enables anonymous usage reporting."""
        self.enabled = True

    def report_error(self, error):
        """Reports an error if anonymous usage reporting is enabled."""

        if self.enabled:
            self._capture_exception(error)


usage_reporting = UsageReporting()
