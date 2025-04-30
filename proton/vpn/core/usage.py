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
import os
import hashlib
import getpass
import re

from proton.vpn.core.session_holder import (
    ClientTypeMetadata, DISTRIBUTION_VERSION, DISTRIBUTION_ID)
from proton.vpn.session.utils import get_desktop_environment

DSN = "https://9a5ea555a4dc48dbbb4cfa72bdbd0899@vpn-api.proton.me/core/v4/reports/sentry/25"
SSL_CERT_FILE = "SSL_CERT_FILE"
MACHINE_ID = "/etc/machine-id"
PROTON_VPN = "protonvpn"

# This is how we anonymise the data sent to us in sentry messages.
#
# The regular expressions will be matched against lower and upper case matches
# so the regular expression doesn't needs to include casing.
#
# {user} is a special key that will be replaced with the username of the
# current user. It makes for a more accurant regex match.
PRIVACY_REPLACEMENTS = [
    # Username in home directory
    (r'\/home\/{user}\/', r"/home/<HIDDEN>/"),
    # Email addresses
    (r'[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{{2,}}', r"<HIDDEN>"),
    # GPG ID addresses
    (r'gpg: encrypted with.*', r"<HIDDEN>"),
]

log = logging.getLogger(__name__)


def scrub_private_data(data, keys):
    """
    Recursively scrub private data from any values in the event.

    :param data: The value that needs to be scrubbed.
    :param keys: A dictionary of values to substitute before evaluating the
        regex replacement.
    :returns: The contents of data with any discovered personal information
        replaced by <HIDDEN>.
    """
    if isinstance(data, (tuple, list)):
        for index, value in enumerate(data):
            data[index] = scrub_private_data(value, keys)
    elif isinstance(data, dict):
        for key, value in data.items():
            data[key] = scrub_private_data(value, keys)
    elif isinstance(data, str):
        for expression, replacement in PRIVACY_REPLACEMENTS:
            pattern = expression.format(**keys)
            data = re.sub(pattern, replacement, data, flags=re.IGNORECASE)
    return data


class UsageReporting:
    """Sends anonymous usage reports to Proton."""

    def __init__(self, client_type_metadata: ClientTypeMetadata):
        self._enabled = False
        self._capture_exception = None
        self._client_type_metadata = client_type_metadata
        self._user_id = None
        self._desktop_environment = get_desktop_environment()

    @property
    def enabled(self):
        """Returns whether anonymous usage reporting is enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool):
        """
        Sets whether usage reporting is enabled/disabled.

        On unsupported platforms, this may fail, in which case UsageReporting
        will be disabled and an exception will be logged.
        """

        try:
            self._enabled = value and self._start_sentry()
        except Exception:  # pylint: disable=broad-except
            self._enabled = False
            log.exception("Failed to enabled usage reporting")

    def report_error(self, error):
        """
        Send an error to sentry if anonymous usage reporting is enabled.

        On unsupported platforms, this may fail, in which case the error will
        will not be reported and an exception will be logged.
        """

        try:
            if self._enabled:
                self._add_scope_metadata()
                self._capture_exception(error)

        except Exception:  # pylint: disable=broad-except
            log.exception("Failed to report error '%s'", str(error))

    @staticmethod
    def _get_user_id(machine_id_filepath=MACHINE_ID, user_name=None):
        """
        Returns a unique identifier for the user.

        :param machine_id_filepath: The path to the machine id file,
            defaults to /etc/machine-id. This can be overrided for testing.

        :param user_name: The username to include in the hash, if None is
            provided, the current user is obtained from the environment.
        """

        if not os.path.exists(machine_id_filepath):
            return None

        # We include the username in the hash to avoid collisions on machines
        # with multiple users.
        if not user_name:
            user_name = getpass.getuser()

        # We use the machine id to uniquely identify the machine, we combine it
        # with the application name and the username. All three are hashed to
        # avoid leaking any personal information.
        with open(machine_id_filepath, "r", encoding="utf-8") as machine_id_file:
            machine_id = machine_id_file.read().strip()

        combined = hashlib.sha256(machine_id.encode('utf-8'))
        combined.update(hashlib.sha256(PROTON_VPN.encode('utf-8')).digest())
        combined.update(hashlib.sha256(user_name.encode('utf-8')).digest())

        return str(combined.hexdigest())

    @staticmethod
    def _sanitize_event(event, _hint, user_name=getpass.getuser()):
        """
        Sanitize the event before sending it to sentry.

        :param event: A dictionary representing the event to sanitize.
        :param _hint: Unused but required by the sentry SDK.
        :param user_name: The username to replace in the event, defaults to the
            current user, but can be set for testing purposes.
        """

        return scrub_private_data(
            event,
            {
                "user": user_name
            }
        )

    def _add_scope_metadata(self):
        """
        Unfortunately, we cannot set the user and tags on the isolation scope
        on startup because this is lost by the time we report an error.
        So we have to set the user and tags on the current scope just before
        reporting an error.
        """
        import sentry_sdk  # pylint: disable=import-outside-toplevel

        # Using configure_scope to set a tag works with older versions of
        # sentry (0.12.2) and so works on ubuntu 20.
        with sentry_sdk.configure_scope() as scope:
            scope.set_tag("distro_name", DISTRIBUTION_ID)
            scope.set_tag("distro_version", DISTRIBUTION_VERSION)
            scope.set_tag("desktop_environment", self._desktop_environment)
            if self._user_id and hasattr(scope, "set_user"):
                scope.set_user({"id": self._user_id})

    def _start_sentry(self):
        """Starts the sentry SDK with the appropriate configuration."""

        if self._capture_exception:
            return True

        if not self._client_type_metadata:
            raise ValueError("Client type metadata is not set, "
                             "UsageReporting.init() must be called first.")

        import sentry_sdk  # pylint: disable=import-outside-toplevel

        from sentry_sdk.integrations.dedupe import DedupeIntegration  # pylint: disable=import-outside-toplevel
        from sentry_sdk.integrations.stdlib import StdlibIntegration  # pylint: disable=import-outside-toplevel
        from sentry_sdk.integrations.modules import ModulesIntegration  # pylint: disable=import-outside-toplevel

        # Read from SSL_CERT_FILE from environment variable, this allows us to
        # use an http proxy if we want to.
        ca_certs = os.environ.get(SSL_CERT_FILE, None)
        client_type_metadata = self._client_type_metadata
        sentry_sdk.init(
            dsn=DSN,
            before_send=UsageReporting._sanitize_event,
            release=f"{client_type_metadata.type}-{client_type_metadata.version}",
            server_name=False,           # Don't send the computer name
            default_integrations=False,  # We want to be explicit about the integrations we use
            integrations=[
                DedupeIntegration(),     # Yes we want to avoid event duplication
                StdlibIntegration(),     # Yes we want info from the standard lib objects
                ModulesIntegration()     # Yes we want to know what python modules are installed
            ],
            ca_certs=ca_certs
        )

        # Store the user id so we don't have to calculate it again.
        self._user_id = self._get_user_id()

        # Store _capture_exception as a member, so it's easier to test.
        self._capture_exception = sentry_sdk.capture_exception

        return True
