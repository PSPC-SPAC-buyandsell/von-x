#
# Copyright 2017-2018 Government of Canada
# Public Services and Procurement Canada - buyandsell.gc.ca
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Methods and classes for working with asyncio event loops
"""

import asyncio
from concurrent.futures import Executor, Future
from threading import get_ident, Event, Thread
from typing import Awaitable, Callable, Coroutine
import logging

LOGGER = logging.getLogger(__name__)


def run_coro(coro: Coroutine):
    """
    Run an async coroutine and wait for the results

    Args:
        coro (CoroutineType): The coroutine to execute
    Returns:
        The result of the coroutine
    """
    event_loop = None
    try:
        event_loop = asyncio.get_event_loop()
    except RuntimeError:
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)
    return event_loop.run_until_complete(coro)


def run_in_executor(executor: Executor, coro: Coroutine) -> Future:
    """
    Run an async coroutine in an executor when we aren't already inside an event loop

    Args:
        executor: A :class:`ThreadExecutor` or :class:`ProcessExecutor` instance which will
            run the coroutine
    Returns:
        A `Future` which can be used to access the result of the coroutine
    """
    loop = asyncio.new_event_loop()
    def _run_sync_loop(loop, coro):
        asyncio.set_event_loop(loop)
        loop.run_until_complete(coro)
    future = executor.submit(_run_sync_loop, loop, coro)
    return future


class Runner:
    """
    Run a new event loop in a separate thread and allow tasks to be submitted to it
    """
    def __init__(self, loop=None):
        self._active = False
        self._loop = loop
        self._thread = None

    @property
    def loop(self):
        """
        Accessor for the event loop instance
        """
        return self._loop

    def start(self, wait: bool = True) -> None:
        """
        Run the event loop in a new thread

        Args:
            wait: block until the event loop is running
        """
        if self._active:
            return
        if not self._loop:
            self._loop = asyncio.new_event_loop()
        event = Event() if wait else None
        self._thread = Thread(target=self._run, args=(event,))
        self._thread.daemon = True
        self._thread.start()
        if event:
            event.wait()

    def _run(self, event=None) -> None:
        """
        The main logic of the event loop thread
        """
        asyncio.set_event_loop(self._loop)
        def _ready():
            self._active = True
            if event:
                event.set()
        self._loop.call_soon(_ready)
        self._loop.run_forever()

    def stop(self, wait: bool = True) -> None:
        """
        Terminate the event loop thread

        Args:
            wait: block until the event loop has been stopped
        """
        def _finish(event):
            self._active = False
            self._loop.stop()
            #pending = asyncio.Task.all_tasks()
            #self._loop.run_until_complete(asyncio.gather(*pending))
            if event:
                event.set()
        if get_ident() == self._thread.ident:
            _finish(None)
        else:
            event = Event() if wait else None
            self._loop.call_soon_threadsafe(_finish, event)
            if event:
                event.wait()
                self.join()

    def join(self):
        """
        Wait for the event loop thread to terminate
        """
        return self._thread.join()

    def _add_task(self, coro: Awaitable, future: Future = None) -> asyncio.Future:
        """
        Add a coroutine to the event loop, to be run at a later time

        Args:
            coro: the coroutine to be added
            future: an optional :class:`Future` used to return the result to another thread
        """
        result = asyncio.ensure_future(coro, loop=self._loop)
        if future:
            future.set_result(result)
        return result

    def run_task(self, coro: Awaitable) -> asyncio.Future:
        """
        Add a coroutine to the event loop, to be run at a later time

        Args:
            coro: the coroutine to be added
        """
        if not self._active:
            raise RuntimeError('Runner is not active')
        if get_ident() == self._thread.ident:
            result = self._add_task(coro)
        else:
            fut = Future()
            self._loop.call_soon_threadsafe(self._add_task, coro, fut)
            result = fut.result()
        return result

    def run_in_executor(self, executor: Executor, func: Callable, *args) -> asyncio.Future:
        """
        Run a function in an executor, in the runner's event loop

        Args:
            executor: the Executor to use, may be None for the default ThreadPoolExecutor
            func: the function to run
            args: arguments to pass to the function
        """
        if not self._active:
            raise RuntimeError('Runner is not active')
        coro = self._loop.run_in_executor(executor, func, *args)
        return self.run_task(coro)
