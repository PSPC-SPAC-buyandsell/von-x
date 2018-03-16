import asyncio
import threading
import logging
logger = logging.getLogger(__name__)

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
    #loop.set_exception_handler(lambda: logger.exception('??'))
    def start_sync_loop(loop):
        asyncio.set_event_loop(loop)
        loop.run_forever()
    t1 = threading.Thread(target=start_sync_loop, args=(loop,))
    t1.start()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    async def done(future):
        loop.stop()
    future.add_done_callback(done)
    return future

def run_in_executor(executor, coro):
    loop = asyncio.new_event_loop()
    #loop.set_exception_handler(lambda: logger.exception('??'))
    def run_sync_loop(loop):
        asyncio.set_event_loop(loop)
        loop.run_until_complete(coro)
    future = executor.submit(run_sync_loop, loop)
    return future
