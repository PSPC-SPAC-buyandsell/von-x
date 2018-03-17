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

import asyncio
import threading
import logging

LOGGER = logging.getLogger(__name__)


def run_coro(coro):
    event_loop = None
    try:
        event_loop = asyncio.get_event_loop()
    except RuntimeError:
        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)
    return event_loop.run_until_complete(coro)


def run_in_thread(coro):
    loop = asyncio.new_event_loop()
    def start_sync_loop(loop):
        asyncio.set_event_loop(loop)
        loop.run_forever()
    thread = threading.Thread(target=start_sync_loop, args=(loop,))
    thread.start()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    async def done(_future):
        loop.stop()
    future.add_done_callback(done)
    return future


def run_in_executor(executor, coro):
    loop = asyncio.new_event_loop()
    def run_sync_loop(loop):
        asyncio.set_event_loop(loop)
        loop.run_until_complete(coro)
    future = executor.submit(run_sync_loop, loop)
    return future
