"""
Copyright (c) 2026 Proton AG

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
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum
from typing import List, TYPE_CHECKING
from pathlib import Path

from proton.utils.environment import VPNExecutionEnvironment
from proton.vpn.session.exceptions import NotificationDecodeError
from proton.vpn.session.utils import RefreshCalculator, rest_api_request
from proton.vpn import logging
from proton.vpn.core.cache_handler import CacheHandler

if TYPE_CHECKING:
    from proton.vpn.session.api import VPNSession

logger = logging.getLogger(__name__)

REFRESH_INTERVAL = 24 * 60 * 60  # 1 day

# pylint: disable=duplicate-code


class NotificationType(IntEnum):
    """Types of pull notification"""
    INVALID = -1
    NPSSURVEY = 4


@dataclass
class NpsSurvey:
    """Represents an NPS survey notification"""
    survey_id: str
    start_time: datetime
    end_time: datetime
    seen: bool

    @property
    def is_active(self) -> bool:
        """Returns whether this NpsSurvey is currently active"""
        now = datetime.now(tz=timezone.utc)
        return self.start_time <= now < self.end_time

    @staticmethod
    def from_dict(data: dict) -> "NpsSurvey":
        """Converts to NpsSurvey object"""
        try:
            return NpsSurvey(
                survey_id=data["NotificationID"],
                start_time=datetime.fromtimestamp(
                    data["StartTime"],
                    tz=timezone.utc
                ),
                end_time=datetime.fromtimestamp(
                    data["EndTime"],
                    tz=timezone.utc
                ),
                seen=data.get("seen", False)
            )
        except (KeyError, TypeError, ValueError) as error:
            raise NotificationDecodeError(
                "Error parsing NpsSurvey pull notification."
            ) from error


class Notifications:  # pylint: disable=too-few-public-methods
    """Contains a record of pulled notifications."""
    def __init__(self, api_data: dict):
        self._api_data = api_data
        self._expiration_time = api_data.get(
            "ExpirationTime",
            RefreshCalculator.get_expiration_time(
                refresh_interval=REFRESH_INTERVAL
            )
        )

    def get_nps_survey_notifications(self) -> List[NpsSurvey]:
        """Get a list of NPS Survey notifications."""
        nps_notifications = []
        for notification in self._api_data.get("Notifications", []):
            notification_type = notification.get("Type", NotificationType.INVALID)
            if notification_type == NotificationType.NPSSURVEY:
                try:
                    nps_notifications.append(NpsSurvey.from_dict(notification))
                except NotificationDecodeError:
                    logger.warning(
                        "NPSSurvey notification could not be deserialized.",
                        exc_info=True
                    )

        return nps_notifications

    @property
    def data(self) -> dict:
        """Returns dict with notification data"""
        return self._api_data

    @property
    def is_expired(self) -> bool:
        """Returns if data has expired"""
        return RefreshCalculator.get_is_expired(self._expiration_time)

    @property
    def seconds_until_expiration(self) -> int:
        """Returns amount of seconds until it expires."""
        return RefreshCalculator.get_seconds_until_expiration(self._expiration_time)

    @staticmethod
    def get_refresh_interval_in_seconds() -> int:
        """Returns refresh interval in seconds."""
        return RefreshCalculator(REFRESH_INTERVAL).get_refresh_interval_in_seconds()


class NotificationsFetcher:
    """Fetches and caches notifications from Proton's REST API."""
    ROUTE = "/core/v4/notifications"
    CACHE_PATH = Path(VPNExecutionEnvironment().path_cache) / "notifications.json"

    def __init__(
        self, session: "VPNSession",
        refresh_calculator: RefreshCalculator = None,
        cache_handler: CacheHandler = None
    ):
        """
        :param session: session used to retrieve notifications.
        """
        self._notifications = None
        self._session = session
        self._refresh_calculator = refresh_calculator or RefreshCalculator
        self._cache_file = cache_handler or CacheHandler(self.CACHE_PATH)

    def clear_cache(self):
        """Discards the cache, if existing."""
        self._notifications = None
        self._cache_file.remove()

    async def fetch(self) -> Notifications:
        """
        Fetches notifications from the REST API.
        :returns: the fetched notifications.
        """
        response = await rest_api_request(
            self._session,
            self.ROUTE,
        )
        response["ExpirationTime"] = self._refresh_calculator\
            .get_expiration_time(refresh_interval=REFRESH_INTERVAL)
        self._propagate_seen_state_to_new_snapshot(response)
        self._cache_file.save(response)
        self._notifications = Notifications(response)

        return self._notifications

    def load_from_cache(self) -> Notifications:
        """
        Loads notifications from the cache.
        :returns: the cached notifications, or an empty and expired Notifications
                  instance if no cache was found (triggering an immediate fetch).
        """
        cache = self._cache_file.load()
        self._notifications = \
            Notifications(cache) if cache else Notifications({"ExpirationTime": 0})
        return self._notifications

    def set_notification_seen(self, seen_notification_id: str):
        """Finds a notification matching the ID and marks it as seen"""
        if self._notifications is None:
            return

        for notification in self._notifications.data.get("Notifications", []):
            if notification_id := notification.get("NotificationID", None):
                if notification_id == seen_notification_id:
                    notification["seen"] = True

        self._cache_file.save(self._notifications.data)

    def _is_notification_seen(self, seen_notification_id: str):
        if self._notifications is None:
            return False

        for notification in self._notifications.data.get("Notifications", []):
            if notification_id := notification.get("NotificationID", None):
                if notification_id == seen_notification_id:
                    return notification.get("seen", False)

        return False

    def _propagate_seen_state_to_new_snapshot(self, new_notification_data: dict):
        for notification in new_notification_data.get("Notifications", []):
            if notification_id := notification.get("NotificationID", None):
                if self._is_notification_seen(notification_id):
                    notification["seen"] = True
