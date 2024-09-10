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
import inspect
from typing import Optional, Callable
from datetime import timedelta
import random

from proton.vpn import logging
from proton.vpn.core.refresher.scheduler import RunAgain
from proton.vpn.core.session_holder import SessionHolder
from proton.vpn.session.credentials import VPNPubkeyCredentials
from proton.session.exceptions import (
    ProtonAPINotReachable, ProtonAPINotAvailable,
)

logger = logging.getLogger(__name__)

# pylint: disable=R0801


class CertificateRefresher:
    """
    Service in charge of refreshing certificate, that is used to derive
    users private keys, to establish VPN connections.
    """

    def __init__(self, session_holder: SessionHolder):
        self._session_holder = session_holder
        self._number_of_failed_refresh_attempts = 0
        self.certificate_updated_callback: Optional[Callable] = None

    @property
    def _session(self):
        return self._session_holder.session

    @property
    def initial_refresh_delay(self):
        """Returns the initial delay before the first refresh."""
        return self._session.vpn_account \
            .vpn_credentials \
            .pubkey_credentials \
            .remaining_time_to_next_refresh

    async def refresh(self) -> RunAgain:
        """Fetches the new certificate from the REST API."""
        try:
            certificate = await self._session.fetch_certificate()
            next_refresh_delay = certificate.remaining_time_to_next_refresh
            self._number_of_failed_refresh_attempts = 0
            await self._notify()
        except (ProtonAPINotReachable, ProtonAPINotAvailable) as error:
            logger.warning(f"Certificate refresh failed: {error}")
            next_refresh_delay = self._get_next_refresh_delay()
            self._number_of_failed_refresh_attempts += 1
        except Exception:
            logger.error(
                "Certificate refresh failed unexpectedly."
                "Stopping certificate refresh."
            )
            raise

        logger_prefix = "Next"
        if self._number_of_failed_refresh_attempts:
            logger_prefix = f"Attempt {self._number_of_failed_refresh_attempts} for"

        logger.info(
            f"{logger_prefix} certificate refresh scheduled in "
            f"{timedelta(seconds=next_refresh_delay)}"
        )

        return RunAgain.after_seconds(next_refresh_delay)

    def _get_next_refresh_delay(self):
        return min(
            generate_backoff_value(self._number_of_failed_refresh_attempts),
            VPNPubkeyCredentials.get_refresh_interval_in_seconds()
        )

    async def _notify(self):
        if self.certificate_updated_callback is None:
            return

        if inspect.iscoroutinefunction(self.certificate_updated_callback):
            await self.certificate_updated_callback()  # pylint: disable=not-callable
        else:
            raise ValueError(
                "Expected coroutine function but found "
                f"{type(self.certificate_updated_callback)}"
            )


def generate_backoff_value(
        number_of_failed_refresh_attempts: int, backoff_in_seconds: int = 1,
        random_component: float = None
) -> int:
    """Generate and return a backoff value for when API calls fail,
    so it can retry again without DDoS'ing the API."""
    random_component = random_component or _generate_random_component()
    return backoff_in_seconds * 2 ** number_of_failed_refresh_attempts * random_component


def _generate_random_component() -> int:
    """Generates random component between 1 - randones_percentage and 1 + randomness_percentage."""
    return 1 + VPNPubkeyCredentials.REFRESH_RANDOMNESS * (2 * random.random() - 1)  # nosec B311
