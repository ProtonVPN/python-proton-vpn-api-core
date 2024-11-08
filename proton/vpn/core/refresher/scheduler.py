"""
Copyright (c) 2024 Proton AG

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
import time
from asyncio import CancelledError

from dataclasses import dataclass
from typing import Optional, Coroutine, List, Callable


@dataclass
class RunAgain:
    """Object to be returned by a task to be run again after a certain amount of time."""
    delay_in_ms: int

    @staticmethod
    def after_seconds(seconds: float):
        """Returns a RunAgain object to be run after a certain amount of seconds."""
        return RunAgain(delay_in_ms=int(seconds * 1000))


@dataclass
class TaskRecord:
    """Record with details of the task to be executed and when."""
    id: int  # pylint: disable=invalid-name
    timestamp: float
    async_function: Callable[[], Coroutine]
    background_task: Optional[asyncio.Task] = None


class Scheduler:
    """
    Task scheduler.

    The goal of this implementation is to improve the accuracy of the built-in scheduler
    when the system is suspended/resumed. The built-in scheduler does not take into account
    the time the system has been suspended after a task has been scheduled to run after a
    certain amount of time. In this case, the clock is paused and then resumed.

    The way this implementation workarounds this issue is by keeping a record of tasks to
    be executed and the timestamp at which they should be executed. Then it periodically
    checks the lists for any tasks that should be executed and runs them.
    """

    def __init__(self, check_interval_in_ms: int = 10_000):
        self._check_interval_in_ms = check_interval_in_ms
        self._error_callback = None
        self._last_task_id: int = 0
        self._task_list: List[TaskRecord] = []
        self._scheduler_task: Optional[asyncio.Task] = None

    def set_error_callback(self, error_callback: Callable[[Exception], None] = None):
        """Sets the error callback to be called when an error occurs while executing a task."""
        self._error_callback = error_callback

    def unset_error_callback(self):
        """Unsets the error callback."""
        self._error_callback = None

    @property
    def task_list(self):
        """Returns the list of tasks currently scheduled."""
        return self._task_list

    @property
    def is_started(self):
        """Returns whether the scheduler has been started or not."""
        return self._scheduler_task is not None

    @property
    def number_of_remaining_tasks(self):
        """Returns the number of remaining tasks to be executed."""
        return len([record for record in self._task_list if not record.background_task])

    def get_tasks_ready_to_fire(self) -> List[TaskRecord]:
        """
        Returns the tasks that are ready to fire, that is the tasks with a timestamp lower or
        equal than the current unix time."""
        now = time.time()
        return list(filter(
            lambda record: record.timestamp <= now and not record.background_task,
            self._task_list
        ))

    def start(self):
        """Starts the scheduler."""
        if self.is_started:  # noqa: E501 # pylint: disable=line-too-long # nosemgrep: python.lang.maintainability.is-function-without-parentheses.is-function-without-parentheses
            raise RuntimeError("Scheduler was already started.")

        self._scheduler_task = asyncio.create_task(self._run_periodic_task_list_check())

    async def stop(self):
        """Stops the scheduler and discards all remaining tasks."""
        if self.is_started:    # noqa: E501 # pylint: disable=line-too-long # nosemgrep: python.lang.maintainability.is-function-without-parentheses.is-function-without-parentheses
            self._scheduler_task.cancel()

            for record in self._task_list:
                if record.background_task:
                    record.background_task.cancel()
            self._task_list = []

            await self.wait_for_shutdown()
            self._scheduler_task = None

    async def wait_for_shutdown(self, timeout=1):
        """Waits for the scheduler to be stopped."""
        if self.is_started:  # noqa: E501 # pylint: disable=line-too-long # nosemgrep: python.lang.maintainability.is-function-without-parentheses.is-function-without-parentheses
            try:
                await asyncio.wait_for(self._scheduler_task, timeout)
            except CancelledError:
                pass

    def run_soon(self, async_function: Callable[[], Coroutine]) -> int:
        """
        Runs the coroutine as soon as possible.
        :returns: the scheduled task id.
        """
        return self.run_after(0, async_function)

    def run_after(
            self, delay_in_seconds: float, async_function: Callable[[], Coroutine]
    ) -> int:
        """
        Runs the coroutine after a delay specified in seconds.
        :returns: the scheduled task id.
        """
        return self.run_at(time.time() + delay_in_seconds, async_function)

    def run_at(
            self, timestamp: float, async_function: Callable[[], Coroutine]
    ) -> int:
        """
        Runs the task at the specified timestamp.
        :returns: the scheduled task id.
        """
        if not inspect.iscoroutinefunction(async_function):
            raise ValueError("A coroutine function was expected.")

        self._last_task_id += 1

        record = TaskRecord(
            id=self._last_task_id,
            timestamp=timestamp,
            async_function=async_function
        )
        self._task_list.append(record)

        return record.id

    def cancel_task(self, task_id):
        """Cancels a task to be executed given its task id."""
        for task in self._task_list:  # noqa: E501 # pylint: disable=line-too-long # nosemgrep: python.lang.correctness.list-modify-iterating.list-modify-while-iterate
            if task.id == task_id:
                if task.background_task:
                    task.background_task.cancel()
                else:
                    self._task_list.remove(task)
                break  # noqa: E501 # pylint: disable=line-too-long # nosemgrep: python.lang.correctness.list-modify-iterating.list-modify-while-iterate

    async def _run_periodic_task_list_check(self):
        while True:
            self.run_tasks_ready_to_fire()
            await asyncio.sleep(self._check_interval_in_ms / 1000)

    def run_tasks_ready_to_fire(self):
        """
        Runs the tasks ready to be executed, that is the tasks with a timestamp lower or equal
        than the current unix time, and removes them from the list.
        """
        tasks_ready_to_fire = self.get_tasks_ready_to_fire()

        # Run the tasks that are ready to be run.
        for task_record in tasks_ready_to_fire:
            task = asyncio.create_task(task_record.async_function())
            task_record.background_task = task
            task.add_done_callback(self._on_task_done)

    def _on_task_done(self, task: asyncio.Task):
        # Get the task record associated with the task.
        task_record = next(filter(lambda record: record.background_task == task, self._task_list))

        result = None
        try:
            # Bubble up exceptions, if any.
            result = task.result()
        except CancelledError:
            # CancelledError is raised when the task is cancelled.
            pass
        except Exception as exc:  # pylint: disable=broad-except
            self._task_list.remove(task_record)
            if not self._error_callback:
                raise exc
            self._error_callback(exc)
            return

        if isinstance(result, RunAgain):
            # if the task record is to be run again then it's rescheduled.
            task_record.timestamp = time.time() + result.delay_in_ms / 1000
            task_record.background_task = None
        else:
            self._task_list.remove(task_record)
