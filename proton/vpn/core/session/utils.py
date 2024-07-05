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
import re
from typing import Optional


import time
import random
import os as sys_os
import json
from dataclasses import asdict
import distro
from proton.vpn import logging

logger = logging.getLogger(__name__)


class Serializable:  # pylint: disable=missing-class-docstring
    """Utility class for dataclasses."""
    def to_json(self) -> str:  # pylint: disable=missing-function-docstring
        return json.dumps(asdict(self))

    def to_dict(self) -> dict:  # pylint: disable=missing-function-docstring
        return asdict(self)

    @classmethod
    def from_dict(cls, dict_data: dict) -> 'Serializable':  # noqa: E501 pylint: disable=missing-function-docstring
        return cls._deserialize(dict_data)

    @classmethod
    def from_json(cls, data: str) -> 'Serializable':  # pylint: disable=missing-function-docstring
        dict_data = json.loads(data)
        return cls._deserialize(dict_data)

    @staticmethod
    def _deserialize(dict_data: dict) -> 'Serializable':
        raise NotImplementedError


class RefreshCalculator:
    """Calculates refresh times based on a set refresh randomness value."""
    def __init__(
        self,
        refresh_interval: int,
        refresh_randomness_in_percentage: float = None
    ):
        """
        The variable refresh_randomness_in_percentage will be used to create a
        deviation from original refresh value.
        Ie: 0.22 == 22% variation, so if we make request every 3h they will
        happen with random deviation between 0% and 22% from the base 3h value.
        """
        self._refresh_interval = refresh_interval
        self._refresh_randomness = refresh_randomness_in_percentage or 0.22

    @staticmethod
    def get_is_expired(expiration_time: float) -> bool:
        """Returns if data has expired"""
        current_time = time.time()
        return current_time > expiration_time

    @staticmethod
    def get_seconds_until_expiration(expiration_time: float) -> float:
        """
        Amount of seconds left until the client configuration is considered
        outdated and should be fetched again from the REST API.
        """
        seconds_left = expiration_time - time.time()
        return seconds_left if seconds_left > 0 else 0

    @staticmethod
    def get_expiration_time(
        refresh_interval: int,
        refresh_randomness: float = None,
        start_time: float = None
    ) -> float:  # noqa: E501 pylint: disable=missing-function-docstring
        """Returns the expiration time based on either a defined start time or current time."""
        start_time = start_time if start_time is not None else time.time()
        refresh_calculator = RefreshCalculator(refresh_interval, refresh_randomness)

        return start_time + refresh_calculator.get_refresh_interval_in_seconds()

    def get_refresh_interval_in_seconds(self) -> float:  # noqa pylint: disable=missing-function-docstring
        return self._refresh_interval * self._generate_random_component()

    def _generate_random_component(self):
        return 1 + self._refresh_randomness * (2 * random.random() - 1)  # nosec B311


async def rest_api_request(session, route, **api_request_kwargs):  # noqa: E501 pylint: disable=missing-function-docstring
    logger.info(f"'{route}'", category="api", event="request")
    response = await session.async_api_request(
        route, **api_request_kwargs
    )
    logger.info(f"'{route}'", category="api", event="response")
    return response


def to_semver_build_metadata_format(value: Optional[str]) -> Optional[str]:
    """
    Formats the input value in a format that complies with
    semver's build metadata specs (https://semver.org/#spec-item-10).
    """
    if value is None:
        return None

    value = value.replace("_", "-")
    # Any character not allowed by semver's build metadata suffix
    # specs (https://semver.org/#spec-item-10) is removed.
    value = re.sub(r"[^a-zA-Z0-9\-]", "", value)
    return value


def get_desktop_environment() -> str:
    """Returns the current desktop environment"""
    return sys_os.environ.get('XDG_CURRENT_DESKTOP', "Unknown DE")


def get_distro_variant() -> str:
    """Returns the current distro environment"""
    distro_variant = distro.os_release_attr('variant')
    return f"; {distro_variant}" if distro_variant else ""


def get_distro_version() -> str:
    """Returns the string containing the distro version:
    ie:
     - Fedora: "39"/"40"
    """
    return distro.version()


def generate_os_string() -> str:
    """Returns a string which contains information such as the distro, desktop environment
    and distro variant if it exists"""
    return f"{distro.id()} ({get_desktop_environment()}{get_distro_variant()})"
