"""
Implementation of the Publisher/Subscriber used to signal VPN connection
state changes.


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
import asyncio
import inspect
from typing import Callable, List, Optional

from proton.vpn import logging

logger = logging.getLogger(__name__)


class Publisher:
    """Simple generic implementation of the publish-subscribe pattern."""

    def __init__(self, subscribers: Optional[List[Callable]] = None):
        self._subscribers = subscribers or []
        self._pending_tasks = set()

    def register(self, subscriber: Callable):
        """
        Registers a subscriber to be notified of new updates.

        The subscribers are not expected to block, as they will be notified
        sequentially, one after the other in the order in which they were
        registered.

        :param subscriber: callback that will be called with the expected
            args/kwargs whenever there is an update.
        :raises ValueError: if the subscriber is not callable.
        """
        if not callable(subscriber):
            raise ValueError(f"Subscriber to register is not callable: {subscriber}")

        if subscriber not in self._subscribers:
            self._subscribers.append(subscriber)

    def unregister(self, subscriber: Callable):
        """
        Unregisters a subscriber.

        :param subscriber: the subscriber to be unregistered.
        """
        if subscriber in self._subscribers:
            self._subscribers.remove(subscriber)

    def notify(self, *args, **kwargs):
        """
        Notifies the subscribers about a new update.

        All subscribers will be called

        Each backend and/or protocol have to call this method whenever the connection
        state changes, so that each subscriber can receive states changes whenever they occur.

            :param connection_status: the current status of the connection
            :type connection_status: ConnectionStateEnum

        """
        for subscriber in self._subscribers:
            try:
                if inspect.iscoroutinefunction(subscriber):
                    notification_task = asyncio.create_task(subscriber(*args, **kwargs))
                    self._pending_tasks.add(notification_task)
                    notification_task.add_done_callback(self._pending_tasks.discard)
                else:
                    subscriber(*args, **kwargs)
            except Exception:  # pylint: disable=broad-except
                logger.exception(f"An error occurred notifying subscriber {subscriber}.")

    def is_subscriber_registered(self, subscriber: Callable) -> bool:
        """Returns whether a subscriber is registered or not."""
        return subscriber in self._subscribers

    @property
    def number_of_subscribers(self) -> int:
        """Number of currently registered subscribers."""
        return len(self._subscribers)
