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
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch

import pytest

from proton.vpn.session.notifications_fetcher import (
    NotificationsFetcher, Notifications, NpsSurvey, NotificationType
)
from proton.vpn.session.exceptions import NotificationDecodeError

NOTIFICATION_ID = "NpsSurvey"
_now = datetime.now(tz=timezone.utc)
START_TIME_PAST = int((_now - timedelta(days=1)).timestamp())
END_TIME_FUTURE = int((_now + timedelta(days=1)).timestamp())


@pytest.fixture
def notification_dict():
    return {
        "NotificationID": NOTIFICATION_ID,
        "Type": NotificationType.NPSSURVEY,
        "StartTime": START_TIME_PAST,
        "EndTime": END_TIME_FUTURE,
    }


@pytest.fixture
def api_data(notification_dict):
    return {
        "Code": 1000,
        "Notifications": [notification_dict],
    }


@pytest.fixture
def api_data_with_seen(notification_dict):
    return {
        "Code": 1000,
        "Notifications": [{**notification_dict, "seen": True}],
    }


# ---------------------------------------------------------------------------
# NpsSurvey
# ---------------------------------------------------------------------------

def test_nps_survey_from_dict_converts_unix_timestamps_to_aware_datetimes(notification_dict):
    survey = NpsSurvey.from_dict(notification_dict)

    assert survey.start_time.tzinfo == timezone.utc
    assert survey.end_time.tzinfo == timezone.utc


def test_nps_survey_is_active_within_time_window():
    now = datetime.now(tz=timezone.utc)
    survey = NpsSurvey(
        survey_id="x",
        start_time=now - timedelta(hours=1),
        end_time=now + timedelta(hours=1),
        seen=False,
    )
    assert survey.is_active is True


def test_nps_survey_is_not_active_before_start_time():
    now = datetime.now(tz=timezone.utc)
    survey = NpsSurvey(
        survey_id="x",
        start_time=now + timedelta(hours=1),
        end_time=now + timedelta(hours=2),
        seen=False,
    )
    assert survey.is_active is False


def test_nps_survey_is_not_active_after_end_time():
    now = datetime.now(tz=timezone.utc)
    survey = NpsSurvey(
        survey_id="x",
        start_time=now - timedelta(hours=2),
        end_time=now - timedelta(hours=1),
        seen=False,
    )
    assert survey.is_active is False


def test_nps_survey_seen_defaults_to_false_when_not_in_dict(notification_dict):
    survey = NpsSurvey.from_dict(notification_dict)
    assert survey.seen is False


def test_nps_survey_from_dict_raises_on_missing_required_key():
    with pytest.raises(NotificationDecodeError):
        NpsSurvey.from_dict(
            {
                "StartTime": START_TIME_PAST,
                "EndTime": END_TIME_FUTURE
            }
        )


def test_nps_survey_from_dict_raises_on_invalid_timestamp():
    with pytest.raises(NotificationDecodeError):
        NpsSurvey.from_dict(
            {
                "NotificationID": NOTIFICATION_ID,
                "StartTime": "not-a-timestamp",
                "EndTime": END_TIME_FUTURE
            }
        )


# ---------------------------------------------------------------------------
# NotificationsFetcher — cache
# ---------------------------------------------------------------------------


@patch("proton.vpn.session.notifications_fetcher.rest_api_request")
@pytest.mark.asyncio
async def test_fetch_saves_response_to_cache(mock_rest_api_request, api_data):
    mock_cache_handler = Mock()
    mock_refresh_calculator = Mock()
    mock_refresh_calculator.get_expiration_time.return_value = 10

    mock_rest_api_request.return_value = api_data

    fetcher = NotificationsFetcher(Mock(), mock_refresh_calculator, mock_cache_handler)
    await fetcher.fetch()

    mock_cache_handler.save.assert_called_once()


def test_load_from_cache_returns_notifications_from_cache(api_data):
    mock_cache_handler = Mock()
    mock_cache_handler.load.return_value = api_data

    fetcher = NotificationsFetcher(Mock(), Mock(), mock_cache_handler)
    notifications = fetcher.load_from_cache()

    assert notifications.data["Notifications"] == api_data["Notifications"]


def test_load_from_cache_returns_empty_notifications_when_no_cache_found():
    mock_cache_handler = Mock()
    mock_cache_handler.load.return_value = None

    fetcher = NotificationsFetcher(Mock(), Mock(), mock_cache_handler)
    notifications = fetcher.load_from_cache()

    assert notifications.get_nps_survey_notifications() == []


# ---------------------------------------------------------------------------
# NotificationsFetcher — seen state
# ---------------------------------------------------------------------------

def test_set_notification_seen_marks_notification_as_seen(api_data):
    mock_cache_handler = Mock()
    mock_cache_handler.load.return_value = api_data

    fetcher = NotificationsFetcher(Mock(), Mock(), mock_cache_handler)
    notifications = fetcher.load_from_cache()
    fetcher.set_notification_seen(NOTIFICATION_ID)

    assert notifications.data["Notifications"][0]["seen"] is True


def test_set_notification_seen_persists_seen_state_to_cache(api_data):
    mock_cache_handler = Mock()
    mock_cache_handler.load.return_value = api_data

    fetcher = NotificationsFetcher(Mock(), Mock(), mock_cache_handler)
    fetcher.load_from_cache()

    mock_cache_handler.save.reset_mock()
    fetcher.set_notification_seen(NOTIFICATION_ID)

    mock_cache_handler.save.assert_called_once()
    saved_data = mock_cache_handler.save.call_args[0][0]
    assert saved_data["Notifications"][0]["seen"] is True


@patch("proton.vpn.session.notifications_fetcher.rest_api_request")
@pytest.mark.asyncio
async def test_fetch_propagates_seen_state_to_new_api_snapshot(mock_rest_api_request, api_data):
    mock_cache_handler = Mock()
    mock_refresh_calculator = Mock()
    mock_refresh_calculator.get_expiration_time.return_value = 10

    mock_cache_handler.load.return_value = api_data

    fresh_api_data = api_data.copy()

    fetcher = NotificationsFetcher(Mock(), mock_refresh_calculator, mock_cache_handler)
    fetcher.load_from_cache()
    fetcher.set_notification_seen(NOTIFICATION_ID)

    # API returns fresh snapshot for the same notification ID, without seen
    mock_rest_api_request.return_value = fresh_api_data

    notifications = await fetcher.fetch()

    assert notifications.data["Notifications"][0]["seen"] is True


@patch("proton.vpn.session.notifications_fetcher.rest_api_request")
@pytest.mark.asyncio
async def test_fetch_does_not_mark_unseen_notification_as_seen(mock_rest_api_request, api_data):
    mock_cache_handler = Mock()
    mock_refresh_calculator = Mock()
    mock_refresh_calculator.get_expiration_time.return_value = 10

    mock_cache_handler.load.return_value = api_data

    fetcher = NotificationsFetcher(Mock(), mock_refresh_calculator, mock_cache_handler)
    fetcher.load_from_cache()
    # Deliberately do NOT call set_notification_seen

    mock_rest_api_request.return_value = api_data

    notifications = await fetcher.fetch()

    assert notifications.data["Notifications"][0].get("seen", False) is False


@patch("proton.vpn.session.notifications_fetcher.rest_api_request")
@pytest.mark.asyncio
async def test_fetch_does_not_propagate_seen_to_different_notification_id(mock_rest_api_request, api_data):
    mock_cache_handler = Mock()
    mock_refresh_calculator = Mock()
    mock_refresh_calculator.get_expiration_time.return_value = 10

    mock_cache_handler.load.return_value = api_data

    fetcher = NotificationsFetcher(Mock(), mock_refresh_calculator, mock_cache_handler)
    fetcher.load_from_cache()
    fetcher.set_notification_seen(NOTIFICATION_ID)

    # API returns a different notification ID
    different_id_data = {
        "Code": 1000,
        "Notifications": [
            {
                "NotificationID": "survey-2",
                "Type": NotificationType.NPSSURVEY,
                "StartTime": START_TIME_PAST,
                "EndTime": END_TIME_FUTURE,
            }
        ],
    }
    mock_rest_api_request.return_value = different_id_data

    notifications = await fetcher.fetch()

    assert notifications.data["Notifications"][0].get("seen", False) is False


# ---------------------------------------------------------------------------
# Notifications.get_nps_survey_notifications
# ---------------------------------------------------------------------------

def test_get_nps_survey_notifications_returns_only_nps_type():
    data = {
        "Notifications": [
            {
                "NotificationID": NOTIFICATION_ID,
                "Type": NotificationType.NPSSURVEY,
                "StartTime": START_TIME_PAST,
                "EndTime": END_TIME_FUTURE,
            },
            {
                "NotificationID": "other-1",
                "Type": 99,
                "StartTime": START_TIME_PAST,
                "EndTime": END_TIME_FUTURE,
            },
        ]
    }

    notifications = Notifications(data)
    results = notifications.get_nps_survey_notifications()

    assert len(results) == 1
    assert results[0].survey_id == NOTIFICATION_ID


def test_get_nps_survey_notifications_skips_notification_with_missing_type():
    data = {
        "Notifications": [
            {
                "NotificationID": NOTIFICATION_ID,
                "StartTime": START_TIME_PAST,
                "EndTime": END_TIME_FUTURE,
            }
        ]
    }

    notifications = Notifications(data)
    assert notifications.get_nps_survey_notifications() == []


def test_get_nps_survey_notifications_skips_notification_with_invalid_type():
    data = {
        "Notifications": [
            {
                "NotificationID": NOTIFICATION_ID,
                "Type": NotificationType.INVALID,
                "StartTime": START_TIME_PAST,
                "EndTime": END_TIME_FUTURE,
            }
        ]
    }

    notifications = Notifications(data)
    assert notifications.get_nps_survey_notifications() == []


def test_get_nps_survey_notifications_skips_malformed_notifications():
    data = {
        "Notifications": [
            {
                # Missing NotificationID — should be skipped, not raise
                "Type": NotificationType.NPSSURVEY,
                "StartTime": START_TIME_PAST,
                "EndTime": END_TIME_FUTURE,
            }
        ]
    }

    notifications = Notifications(data)
    assert notifications.get_nps_survey_notifications() == []


def test_get_nps_survey_notifications_reflects_seen_state():
    data = {
        "Notifications": [
            {
                "NotificationID": NOTIFICATION_ID,
                "Type": NotificationType.NPSSURVEY,
                "StartTime": START_TIME_PAST,
                "EndTime": END_TIME_FUTURE,
                "seen": True,
            }
        ]
    }

    notifications = Notifications(data)
    results = notifications.get_nps_survey_notifications()

    assert results[0].seen is True
