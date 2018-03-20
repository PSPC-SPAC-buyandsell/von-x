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
import collections
import logging
import os
import time
import traceback

import multiprocessing as mp
from threading import Condition, Thread, get_ident
from concurrent.futures import ThreadPoolExecutor

LOGGER = logging.getLogger(__name__)


class ExchangeError:
    def __init__(self, value, exc_info=None):
        self.value = value
        if exc_info is True:
            # cannot pass real exception or traceback through the message pipe
            exc_info = traceback.format_exc()
        self.exc_info = exc_info
    def format(self):
        ret = '{}'.format(self.value)
        if self.exc_info:
            ret += "\n" + str(self.exc_info)
        return ret


class Exchange:
    """
    A central message exchange hub for receiving requests and passing them to processors
    which may live in a different thread or process, but have a known identifier.
    Multiple processors may also respond to the same identifier to split requests.
    Responses are optional and can be tied to the original request.
    """

    def __init__(self):
        self._cmd_pipe = mp.Pipe()
        self._cmd_lock = mp.Lock()
        self._req_cond = mp.Condition(mp.Lock())

    def start(self, process=True):
        if process:
            runner = mp.Process(target=self.run)
        else:
            runner = Thread(target=self.run)
        runner.daemon = True
        runner.start()
        return runner

    def stop(self):
        with self._req_cond:
            return self._cmd('stop')

    def status(self):
        with self._req_cond:
            return self._cmd('status')

    def _cmd(self, *command):
        # Lock ensures that each command send has a corresponding recv
        with self._cmd_lock:
            self._cmd_pipe[1].send(command)
            return self._cmd_pipe[1].recv()

    def send(self, to_pid, from_pid, ident, message, ref=None):
        # Blocks until we have access to the message queues and command pipe
        # FIXME add a maximum buffer size for the message queues and allow blocking
        # until there is room in the buffer (optional blocking=True argument)
        with self._req_cond:
            LOGGER.debug('send to %s/%s %s', to_pid, ref, message)
            status = self._cmd('send', to_pid, (from_pid, ident, message, ref))
            # wake all threads waiting for an incoming message
            self._req_cond.notify_all()
        return status

    def recv(self, to_pid, blocking=True, timeout=None):
        #pylint: disable=broad-except
        try:
            LOGGER.debug('recv %s', to_pid)
            locked = self._req_cond.acquire(blocking)
            message = None
            if locked:
                message = self._cmd('recv', to_pid)
                while message is None and (blocking or timeout != None):
                    locked = self._req_cond.wait(timeout)
                    if locked:
                        message = self._cmd('recv', to_pid)
                    if not locked or message != None or timeout != None:
                        break
                if locked:
                    self._req_cond.release()
        except Exception:
            LOGGER.exception('Error in recv:')
            raise
        return message

    def run(self):
        #pylint: disable=broad-except
        pending = 0
        processed = {}
        queue = {}
        try:
            while True:
                command = self._cmd_pipe[0].recv()
                if command[0] == 'send':
                    to_pid = command[1]
                    if to_pid not in queue:
                        queue[to_pid] = collections.deque()
                    queue[to_pid].append(command[2])
                    pending += 1
                    self._cmd_pipe[0].send(True)
                elif command[0] == 'recv':
                    to_pid = command[1]
                    message = None
                    if to_pid in queue:
                        try:
                            message = queue[to_pid].popleft()
                            processed[to_pid] = processed.get(to_pid, 0) + 1
                            pending -= 1
                        except IndexError:
                            pass
                    # FIXME clean up expired requests here?
                    # might want to return a message to the sender that the
                    # message couldn't be delivered (an ExchangeError)
                    self._cmd_pipe[0].send(message)
                elif command[0] == 'status':
                    total = sum(processed.values())
                    self._cmd_pipe[0].send({
                        'pending': pending,
                        'processed': processed,
                        'total': total})
                elif command[0] == 'stop':
                    # FIXME optionally block new requests and wait until remaining
                    # messages are processed
                    self._cmd_pipe[0].send(True)
                    break
                else:
                    raise ValueError('Unrecognized command: {}'.format(command[0]))
        except Exception:
            LOGGER.exception('Error in exchange:')



class RequestProcessor:
    """
    A generic message processor which polls the exchange for messages sent to
    this endpoint and runs the abstract 'process' method to perform actions
    and send responses.
    """

    def __init__(self, pid, exchange: Exchange):
        self._pid = pid
        self._exchange = exchange

    def get_pid(self):
        return self._pid

    def get_exchange(self):
        return self._exchange

    def get_endpoint(self, pid):
        return Endpoint(pid, self._exchange, self._pid)

    def start(self):
        # FIXME start exchange here if it's not running? need to track running status
        thread = Thread(target=self.run)
        thread.start()
        return thread

    def stop(self, _wait=True):
        return self.send_noreply(self._pid, 'stop')

    def run(self):
        #pylint: disable=broad-except
        try:
            while True:
                from_pid, ident, message, ref = self._exchange.recv(self._pid)
                LOGGER.debug('%s processing message: %s', self._pid, message)
                if message == 'stop':
                    break
                # FIXME catch exception here and return it to the sender
                try:
                    if self.process(from_pid, ident, message, ref) is False:
                        break
                except Exception:
                    if isinstance(message, ExchangeError):
                        LOGGER.error(message.format())
                    else:
                        errmsg = ExchangeError('Exception during message processing', True)
                        self.send_noreply(from_pid, errmsg, ident)
        except Exception:
            LOGGER.exception('Exception while processing message:')

    def send(self, to_pid, ident, message, ref=None, from_pid=None):
        return self._exchange.send(to_pid, from_pid or self._pid, ident, message, ref)

    def send_noreply(self, to_pid, message, ref=None, from_pid=None):
        return self._exchange.send(to_pid, from_pid or self._pid, None, message, ref)

    def process(self, from_pid, ident, message, ref):
        pass


class RequestExecutor(RequestProcessor):
    """
    An implementation of RequestProcessor which starts a thread for each outgoing request
    to wait for responses. One of these should live in each process which wants to perform
    async requests via the Exchange (like a webserver process). It normally assumes that
    all incoming messages are simply responses to earlier requests.
    Should not block the main thread (much) to avoid breaking asyncio.
    """

    def __init__(self, pid, exchange: Exchange, max_workers=10):
        super(RequestExecutor, self).__init__(pid, exchange)
        self._max_workers = max_workers
        self._pool = None
        self._req_cond = Condition()
        self._requests = {}

    def start(self):
        self._pool = ThreadPoolExecutor(self._max_workers) #thread_name_prefix=self._pid
        # Poll for results in a thread from our thread pool
        return self._pool.submit(self.run)

    # In the webserver environment, the process we're concerned with has already started
    # so just use start() instead
    def start_process(self):
        proc = mp.Process(target=lambda: self.start().result())
        proc.start()
        return proc

    def get_pool(self):
        return self._pool

    def stop(self, wait=True):
        self._pool.shutdown(wait)
        super(RequestExecutor, self).stop(wait)

    def get_endpoint(self, pid):
        return ExecutorEndpoint(self, pid)

    def submit(self, to_pid, message, async_loop=None, timeout=None):
        request = {'result': None}
        ident = id(request)
        result = None
        with self._req_cond:
            self._requests[ident] = request
        result = self.send(to_pid, ident, message)
        if not result:
            raise RuntimeError('Request could not be processed')
        if async_loop:
            if async_loop is True:
                async_loop = asyncio.get_event_loop()
            result = async_loop.run_in_executor(self._pool, self._receive, ident, timeout)
        else:
            result = self._pool.submit(self._receive, ident, timeout)
        return result

    def process(self, from_pid, ident, message, ref):
        with self._req_cond:
            if ref in self._requests:
                self._requests[ref]['result'] = message
                self._req_cond.notify_all()
            else:
                LOGGER.debug('unhandled message to %s/%s from %s: %s',
                             self._pid, ref, from_pid, message)

    def _receive(self, ident, timeout=None):
        with self._req_cond:
            ret = None
            if ident in self._requests:
                ret = self._requests[ident]['result']
                while ret is None:
                    self._req_cond.wait(timeout)
                    if ident not in self._requests:
                        LOGGER.debug('Ident not found in requests')
                        break
                    ret = self._requests[ident]['result']
                    if ret != None or timeout != None:
                        break
            else:
                LOGGER.debug('Ident not found in requests')
            del self._requests[ident]
        return ret


class Endpoint:
    """
    A wrapper for sending messages to a single target.
    Sample usage:
        manager = Endpoint(manager_pid, exchange, my_pid)
        _ = manager.send_noreply('hello')
    """

    def __init__(self, pid, exchange, from_pid=None):
        self._pid = pid
        self._from_pid = from_pid
        self._exchange = exchange

    def get_pid(self):
        return self._pid

    def get_exchange(self):
        return self._exchange

    def get_from_pid(self):
        return self._from_pid

    def send(self, ident, message, ref, from_pid=None):
        return self._exchange.send(
            self._pid,
            from_pid if from_pid != None else self._from_pid,
            ident,
            message,
            ref)

    def send_noreply(self, message, ref, from_pid=None):
        return self.send(None, message, ref, from_pid)


class ExecutorEndpoint(Endpoint):
    """
    An endpoint for a RequestExecutor which uses submit() to poll
    for responses to requests.
    """

    def __init__(self, executor, pid, async_loop=None):
        self._executor = executor
        self._async_loop = async_loop
        super(ExecutorEndpoint, self).__init__(
            pid,
            self._executor.get_exchange(),
            self._executor.get_pid()
        )

    def get_async_loop(self):
        return self._async_loop

    def set_async_loop(self, async_loop):
        self._async_loop = async_loop

    def get_executor(self):
        return self._executor

    def request(self, message, async_loop=None, timeout=None):
        return self._executor.submit(
            self.get_pid(),
            message,
            async_loop=async_loop if async_loop != None else self._async_loop,
            timeout=timeout)



class HelloProcessor(RequestProcessor):
    """
    A simple request processor for testing response functionality or stress testing
    """
    def process(self, from_pid, ident, message, ref):
        self.send_noreply(from_pid, 'hello from {} {}'.format(os.getpid(), get_ident()), ident)


class ThreadedHelloProcessor(HelloProcessor):
    """
    A threaded request processor for testing delayed, blocking and non-blocking responses
    """
    def __init__(self, pid, exchange, blocking=False, max_workers=5):
        super(ThreadedHelloProcessor, self).__init__(pid, exchange)
        self._blocking = blocking
        self._pool = None
        self._max_workers = max_workers

    def start(self):
        self._pool = ThreadPoolExecutor(self._max_workers) #thread_name_prefix=self._pid
        return self._pool.submit(self.run)

    def start_process(self):
        proc = mp.Process(target=lambda: self.start().result())
        proc.start()
        return proc

    def process(self, from_pid, ident, message, ref):
        if self._blocking:
            self._delayed_process((from_pid, ident, message, ref))
        else:
            self._pool.submit(self._delayed_process, message)

    def _delayed_process(self, message):
        time.sleep(1)
        return super(ThreadedHelloProcessor, self).process(*message)


# Testing two workers dividing requests:
# hello = ThreadedHelloProcessor('hello', exchange, blocking=True)
# hello.start_process()
# hello.start_process()
# .. exchange.send('hello', None, None, 'poke') ..
