import time
from unittest.mock import AsyncMock

import pytest

from proton.vpn.core.refresher.scheduler import Scheduler


async def dummy():
    pass


@pytest.mark.asyncio
async def test_start_runs_tasks_ready_to_fire_periodically():
    scheduler = Scheduler(check_interval_in_ms=10)

    task_1 = AsyncMock()
    async def task_1_wrapper():
        await task_1()

    scheduler.run_after(0, task_1_wrapper)

    task_2 = AsyncMock()
    async def run_task_2_and_shutdown():
        await task_2()
        await scheduler.stop()  # stop the scheduler after the second task is executed.

    in_100_ms = time.time() + 0.1
    scheduler.run_at(in_100_ms, run_task_2_and_shutdown)

    scheduler.start()

    await scheduler.wait_for_shutdown()
    task_1.assert_called_once()
    task_2.assert_called_once()
    assert len(scheduler.task_list) == 0


@pytest.mark.asyncio
async def test_run_task_ready_to_fire_only_runs_tasks_with_expired_timestamps():
    scheduler = Scheduler()

    # should run since the delay is 0 seconds.
    scheduler.run_after(delay_in_seconds=0, async_function=dummy)
    # should not run yet since the delay is 30 seconds.
    scheduler.run_after(delay_in_seconds=30, async_function=dummy)
    scheduler.run_tasks_ready_to_fire()

    assert scheduler.number_of_remaining_tasks == 1


@pytest.mark.asyncio
async def test_stop_empties_task_list():
    scheduler = Scheduler()
    scheduler.start()

    scheduler.run_after(delay_in_seconds=30, async_function=dummy)
    await scheduler.stop()

    assert not scheduler.is_started
    assert len(scheduler.task_list) == 0


def test_run_at_schedules_new_task():
    scheduler = Scheduler()

    task_id = scheduler.run_at(timestamp=time.time() + 10, async_function=dummy)

    scheduler.task_list[0].id == task_id


def test_cancel_task_removes_task_from_task_list():
    scheduler = Scheduler()

    task_id = scheduler.run_after(0, dummy)
    scheduler.cancel_task(task_id)

    assert scheduler.number_of_remaining_tasks == 0
