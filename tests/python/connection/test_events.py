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
from unittest.mock import Mock

from proton.vpn.connection import events
from proton.vpn.connection.enum import StateMachineEventEnum
import pytest

from proton.vpn.connection.events import EventContext

context = EventContext(connection=Mock())


def test_base_class_missing_event():
    class DummyEvent(events.Event):
        pass

    with pytest.raises(AttributeError):
        DummyEvent(context)


def test_base_class_expected_event():
    custom_event = "test_event"

    class DummyEvent(events.Event):
        type = custom_event

    assert DummyEvent(context).type == custom_event


@pytest.mark.parametrize(
    "event_class, expected_event",
    [
        (events.Up.type, StateMachineEventEnum.UP),
        (events.Down.type, StateMachineEventEnum.DOWN),
        (events.Connected.type, StateMachineEventEnum.CONNECTED),
        (events.Disconnected.type, StateMachineEventEnum.DISCONNECTED),
        (events.Timeout.type, StateMachineEventEnum.TIMEOUT),
        (events.AuthDenied.type, StateMachineEventEnum.AUTH_DENIED),
        (events.UnexpectedError.type, StateMachineEventEnum.UNEXPECTED_ERROR),
    ]
)
def test_individual_events(event_class, expected_event):
    assert event_class == expected_event
