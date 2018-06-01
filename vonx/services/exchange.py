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
from typing import Callable

from concurrent.futures import Future, ThreadPoolExecutor
import multiprocessing as mp
from threading import Condition, Thread, get_ident

import aiohttp

from . import eventloop

LOGGER = logging.getLogger(__name__)


class ExchangeError:
    """
    An error class to represent an exception in message processing

    This is not a subclass of :class:`Exception` as that cannot be pickled
    and transported over the message bus
    """
    def __init__(self, value, exc_info=True):
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

    def __repr__(self):
        return 'ExchangeError(value={})'.format(self.value)


Message = collections.namedtuple('Message', ('from_pid', 'ident', 'body', 'ref'))
Message.__new__.__defaults__ = (None,)
Message.__doc__ = """
    A wrapper for a message being passed through the :class:`Exchange` message bus

    Attributes:
        from_pid (str): The identifier of the sending service
        ident: A unique identifier for the message, used to tag responses
        body: The content of the message
        ref: An optional identifier for the message being responded to
"""


class Exchange:
    """
    A central message exchange hub for receiving requests and passing them to processors
    which may live in a different thread or process, but have a known identifier.
    Multiple processors may also respond to the same identifier in order to share processing.
    Responses are optional and can be tied to the original request.
    """

    def __init__(self):
        self._cmd_pipe = mp.Pipe()
        self._cmd_lock = mp.Lock()
        self._req_cond = mp.Condition(mp.Lock())

    def start(self, process: bool = True):
        if process:
            runner = mp.Process(target=self.run)
        else:
            runner = Thread(target=self.run)
        runner.daemon = True
        runner.start()
        return runner

    def stop(self):
        """
        Send a stop signal to the polling thread
        """
        with self._req_cond:
            return self._cmd('stop')

    def status(self) -> dict:
        """
        Retrieve the status from the polling thread

        Returns:
            A dict in the form {'pending': int, 'processed': int, 'total': int}
            representing the total numbers of messages handled by the exchange
        """
        with self._req_cond:
            return self._cmd('status')

    def _cmd(self, *command):
        """
        Execute a command against the exchange, using a process lock to synchronize
        requests and responses.
        Supported commands are currently `send`, `recv`, `status` and `stop`
        """
        with self._cmd_lock:
            self._cmd_pipe[1].send(command)
            return self._cmd_pipe[1].recv()

    def send(self, to_pid: str, message: Message) -> bool:
        """
        Add a message to the bus, blocking until the processing thread is ready

        Args:
            to_pid: The identifier for the receiving service
            message: The message to be added to the queue

        Returns:
            True if the message is successfully added to the queue
        """
        # Blocks until we have access to the message queues and command pipe
        # FIXME add a maximum buffer size for the message queues and allow blocking
        # until there is room in the buffer (optional blocking=True argument)
        with self._req_cond:
            LOGGER.debug('send to %s/%s %s', to_pid, message.ref, message.body)
            status = self._cmd('send', to_pid, message)
            # wake all threads waiting for an incoming message
            self._req_cond.notify_all()
        return status

    def recv(self, to_pid: str, blocking: bool = True, timeout=None) -> Message:
        """
        Receive a message from the bus

        Args:
            to_pid: The identifier of the recipient service
            blocking: Whether to sleep this thread until a message is received
            timeout: An optional timeout before aborting

        Returns:
            The next message in the queue, or None
        """
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

    def run(self) -> None:
        """
        The message processing loop
        """
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


class MessageTarget:
    """
    A wrapper for sending messages to a single target.

    Example:
        >>> target = MessageTarget(target_pid, exchange, my_pid)
        >>> target.send_noreply('hello')
        True
    """

    def __init__(self, pid: str, exchange: Exchange, from_pid: str = None):
        self._pid = pid
        self._from_pid = from_pid
        self._exchange = exchange

    @property
    def pid(self) -> str:
        """
        Accessor for the identifier of the recipient service
        """
        return self._pid

    @property
    def exchange(self) -> Exchange:
        """
        Accessor for the :class:`Exchange` used by this target
        """
        return self._exchange

    @property
    def from_pid(self) -> str:
        """
        Accessor for the identifier of the sending service
        """
        return self._from_pid

    def send(self, ident, message, ref=None, from_pid=None) -> bool:
        """
        Send a message to the recipient service

        Args:
            ident: The identifier used by the message response
            message: The message being sent
            ref: An optional identifier for the message being responded to
            from_pid: An optional override for the sender identifier

        Returns:
            True if the message was successfully added to the queue
        """
        return self._exchange.send(self._pid, Message(
            from_pid if from_pid != None else self._from_pid,
            ident,
            message,
            ref))

    def send_noreply(self, message, ref=None, from_pid=None) -> bool:
        """
        Send a message with no reply expected

        Returns:
            True if the message was successfully added to the queue
        """
        return self.send(None, message, ref, from_pid)


class MessageProcessor:
    """
    A generic message processor which polls the exchange for messages sent to
    this endpoint and runs the abstract 'process' method to perform actions
    and send responses.
    """

    def __init__(self, pid: str, exchange: Exchange):
        self._pid = pid
        self._exchange = exchange
        self._thread = None

    @property
    def pid(self) -> str:
        """
        Accessor for the identifier of this request processor service
        """
        return self._pid

    @property
    def exchange(self) -> Exchange:
        """
        Accessor for the :class:`Exchange` used by this request processor
        """
        return self._exchange

    def get_message_target(self, pid) -> MessageTarget:
        """
        Quickly create a :class:`MessageTarget` for a service on the same message bus
        """
        return MessageTarget(pid, self._exchange, self._pid)

    def start(self) -> Thread:
        """
        Run a thread to poll for received messages
        """
        # FIXME start exchange here if it's not running? need to track running status
        self._thread = Thread(target=self.run)
        self._thread.start()
        return self._thread

    def join(self):
        """
        Await our polling thread. `stop()` must be called in order to cause it to abort
        """
        if self._thread:
            return self._thread.join()
        return None

    def stop(self, _wait: bool = True) -> bool:
        """
        Send a stop signal to the polling thread in order to abort polling

        Returns:
            True if the message was successfully processed
        """
        return self.send_noreply(self._pid, 'stop')

    def run(self) -> None:
        """
        The polling loop for receiving messages from the exchange
        """
        #pylint: disable=broad-except
        try:
            while True:
                message = self._exchange.recv(self._pid)
                LOGGER.debug('%s processing message: %s', self._pid, message.body)
                if message.body == 'stop':
                    break
                # FIXME catch exception here and return it to the sender
                try:
                    if self.process(message) is False:
                        break
                except Exception:
                    if isinstance(message.body, ExchangeError):
                        LOGGER.error(message.body.format())
                    else:
                        errmsg = ExchangeError('Exception during message processing', True)
                        self.send_noreply(message.from_pid, errmsg, message.ident)
        except Exception:
            LOGGER.exception('Exception while processing message:')

    def send(self, to_pid: str, ident, message, ref=None, from_pid: str = None) -> bool:
        """
        Send a message to a recipient on the exchange

        Args:
            to_pid: The identifier of the recipient
            ident: The identifier of thie message, to be used by responses
            message: The content of the message
            ref: The identifier of the message being responded to
            from_pid: An optional override for the sender identifier

        Returns:
            True if the message was successfully added to the queue
        """
        return self._exchange.send(to_pid, Message(from_pid or self._pid, ident, message, ref))

    def send_noreply(self, to_pid: str, message, ref=None, from_pid: str = None) -> bool:
        """
        Send a message with no reply expected

        Returns:
            True if the message was successfully added to the queue
        """
        return self._exchange.send(to_pid, Message(from_pid or self._pid, None, message, ref))

    def process(self, message: Message) -> bool:
        """
        Process a message from another service and optionally send a message in response

        Returns: `False` if the polling thread should terminate
        """
        pass


class RequestExecutor(MessageProcessor):
    """
    An subclass of :class:`MessageProcessor` which starts a thread for each outgoing request
    to wait for responses. One of these should live in each process which wants to perform
    async requests via the :class:`Exchange` (like a webserver process). It normally assumes that
    all incoming messages are simply responses to earlier requests.
    Processing should not block the main thread (much) to avoid breaking asyncio.
    """

    def __init__(self, pid, exchange: Exchange, max_workers=10):
        super(RequestExecutor, self).__init__(pid, exchange)
        self._connector = None
        self._loop = None
        self._max_workers = max_workers
        self._pool = None
        self._req_cond = Condition()
        self._requests = {}

    def start(self):
        """
        Create a :class:`ThreadPoolExecutor` and run our polling thread to listen for messages
        """
        if not self._loop:
            self._loop = asyncio.get_event_loop()
        self._pool = ThreadPoolExecutor(self._max_workers) #thread_name_prefix=self._pid
        # Poll for results in a thread from our thread pool
        return self.run_task(self.run)

    # In the webserver environment, the process we're concerned with has already started
    # so just use start() instead
    def start_process(self) -> mp.Process:
        """
        Start this executor in a new process
        """
        def start():
            self.init_process()
            self.start()
            self._loop.run_until_complete()
        proc = mp.Process(target=start)
        proc.start()
        return proc

    def init_process(self) -> None:
        """
        Initialize ourselves in a newly started process
        """
        # create new event loop after fork
        asyncio.get_event_loop().close()
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

    @property
    def loop(self):
        """
        Accessor for the event loop used by this :class:`RequestExecutor`
        """
        return self._loop

    @property
    def pool(self) -> ThreadPoolExecutor:
        """
        Accessor for the :class:`ThreadPoolExecutor` used to execute tasks
        """
        return self._pool

    def stop(self, wait: bool = True) -> None:
        """
        Stop our polling thread and any other tasks in progress

        Args:
            wait: whether to wait for the threads to terminate
        """
        super(RequestExecutor, self).stop(wait)
        if self._pool:
            self._pool.shutdown(wait)
        if self._connector:
            self._connector.close()

    def run_task(self, proc: Callable, *args, loop=None) -> Future:
        """
        Add a task to be processed, as either a coroutine or function

        Args:
            proc: the function or coroutine to be run
            args: arguments to pass to the proc, if a function
            loop: override the current asyncio loop
        """
        loop = loop or self._loop
        if asyncio.iscoroutine(proc):
            result = asyncio.run_coroutine_threadsafe(eventloop.ensure_future(proc), loop)
        else:
            result = loop.run_in_executor(self._pool, proc, *args)
        return result

    def submit(self, to_pid: str, message, timeout=None, loop=None) -> Future:
        """
        Submit a message to another service and run a task to poll for the results

        Args:
            to_pid: the identifier of the target service
            message: the body of the message to be sent
            timeout: an optional timeout to wait for a response
            loop: override the current asyncio loop
        """
        request = {'result': None}
        ident = id(request)
        result = None
        with self._req_cond:
            self._requests[ident] = request
        result = self.send(to_pid, ident, message)
        if not result:
            raise RuntimeError('Request could not be processed')
        result = self.run_task(self._receive, ident, timeout, loop=loop)
        return result

    def _handle_response(self, message: Message) -> bool:
        """
        Handle a message received from another service on the exchange by awaking
        any tasks waiting for results

        Args:
            message: the received message to be processed
        """
        if message.ref:
            with self._req_cond:
                if message.ref in self._requests:
                    self._requests[message.ref]['result'] = message.body
                    self._req_cond.notify_all()
                    return True
        return False

    def process(self, message: Message) -> bool:
        """
        Handle a message received from another service on the exchange

        Args:
            message: the received message to be processed
        """
        if not self._handle_response(message):
            LOGGER.debug('unhandled message to %s/%s from %s: %s',
                         self._pid, message.ref, message.from_pid, message.body)

    def _receive(self, ident, timeout=None):
        """
        For a particular listener task, await a response from another service

        Args:
            ident: The identifier of the message we sent
            timeout: An optional timeout (in seconds) before aborting

        Returns:
            The contents of the message we received, or None
        """
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

    @property
    def tcp_connector(self) -> aiohttp.TCPConnector:
        """
        Return a connection pool associated with this event loop which allows HTTP session reuse
        """
        if not self._connector:
            self._connector = aiohttp.TCPConnector()
        return self._connector

    def http_client(self, *args, **kwargs) -> aiohttp.ClientSession:
        """
        Construct an HTTP client using the shared connection pool
        """
        if 'connector' not in kwargs:
            kwargs['connector'] = self.tcp_connector
            kwargs['connector_owner'] = False
        return aiohttp.ClientSession(*args, **kwargs)

    @property
    def http(self):
        """
        A quick accessor for a default HTTP client instance
        """
        return self.http_client()


class RequestTarget:
    """
    An endpoint for a :class:`RequestExecutor` which uses submit() to poll
    for responses to requests. It must be created within the same process as the
    executor instance

    Example:
        >>> target = RequestTarget(executor, target_pid)
        >>> target.request('hello')
        Future<...>
    """

    def __init__(self, executor: RequestExecutor, pid: str, loop=None):
        self._executor = executor
        self._pid = pid
        self._loop = loop

    @property
    def pid(self):
        """
        Accessor for the target service identifier
        """
        return self._pid

    @property
    def loop(self):
        """
        Accessor for the event loop instance
        """
        return self._loop

    @loop.setter
    def loop(self, newloop):
        """
        Setter for the event loop instance
        """
        self._loop = newloop

    @property
    def executor(self):
        """
        Accessor for the :class:`RequestExecutor` instance
        """
        return self._executor

    def request(self, message, timeout=None, loop=None) -> Future:
        """
        Send a request to the recipient service, awaiting the response in
        a method defined by the executor

        Args:
            message: The message to be sent
            timeout: An optional timeout for the message response
            loop: An optional event loop reference
        """
        return self._executor.submit(
            self.pid,
            message,
            timeout=timeout,
            loop=loop or self._loop)


def _create_request_target(self, pid: str, loop=None):
    """
    Create a :class:`RequestTarget` for a specific service
    """
    return RequestTarget(self, pid, loop)
RequestExecutor.get_request_target = _create_request_target


class HelloProcessor(MessageProcessor):
    """
    A simple request processor for testing response functionality or stress testing
    """
    def process(self, message: Message) -> bool:
        self.send_noreply(message.from_pid,
                          'hello from {} {}'.format(os.getpid(), get_ident()), message.ident)


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

    def start_process(self) -> mp.Process:
        proc = mp.Process(target=lambda: self.start().result())
        proc.start()
        return proc

    def process(self, message: Message) -> bool:
        if self._blocking:
            self._delayed_process(message)
        else:
            self._pool.submit(self._delayed_process, message)

    def _delayed_process(self, message: Message) -> bool:
        time.sleep(1)
        return super(ThreadedHelloProcessor, self).process(message)


# Testing two workers dividing requests:
# hello = ThreadedHelloProcessor('hello', exchange, blocking=True)
# hello.start_process()
# hello.start_process()
# .. exchange.send('hello', None, None, 'poke') ..
