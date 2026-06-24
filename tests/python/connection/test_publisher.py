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
from unittest.mock import Mock, AsyncMock

from proton.vpn.connection.publisher import Publisher
import pytest


@pytest.fixture
def subscriber():
    return Mock()


def test_register_registers_subscriber_if_it_was_not_registered_yet(subscriber):
    publisher = Publisher()
    publisher.register(subscriber)
    assert publisher.is_subscriber_registered(subscriber)


def test_register_does_nothing_if_the_subscriber_was_already_registered():
    subscriber = Mock()
    publisher = Publisher(subscribers=[subscriber])
    publisher.register(subscriber)
    assert publisher.number_of_subscribers == 1


def test_register_raises_value_error_if_subscriber_is_not_callable():
    publisher = Publisher()
    with pytest.raises(ValueError):
        publisher.register(None)


def test_unregister_unregisters_subscriber_if_it_was_already_registered(subscriber):
    publisher = Publisher(subscribers=[subscriber])
    publisher.unregister(subscriber)
    assert not publisher.is_subscriber_registered(subscriber)


def test_unregister_does_nothing_if_subscriber_was_never_registered():
    publisher = Publisher()
    publisher.unregister(Mock())
    assert publisher.number_of_subscribers == 0


@pytest.mark.asyncio
async def test_notify_notifies_all_registered_subscribers():
    subscribers = [Mock(), AsyncMock()]
    publisher = Publisher(subscribers=subscribers)
    publisher.notify("arg1", arg2="arg2")
    for subscriber in subscribers:
        subscriber.assert_called_with("arg1", arg2="arg2")


@pytest.mark.asyncio
async def test_notify_catches_and_logs_exceptions_when_notifying_subscribers(caplog):
    subscribers = [Mock(side_effect=RuntimeError("Bad stuff")), Mock()]
    publisher = Publisher(subscribers=subscribers)

    publisher.notify("foo")

    # Assert that, even though the first subscriber raised a RuntimeError,
    # the second one was also notified.
    for subscriber in subscribers:
        subscriber.assert_called_with("foo")

    # Assert that the error was logged.
    errors = [record for record in caplog.records if record.levelname == "ERROR"]
    assert errors
    assert errors[0].msg.startswith("An error occurred notifying subscriber")