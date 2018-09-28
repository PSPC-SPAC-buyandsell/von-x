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
Implementation of the shared Exchange message bus and related classes for sending
and acting upon messages
"""

import asyncio
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
import logging
import multiprocessing as mp
import os
from queue import Queue
from threading import get_ident, Event, Thread
import time
import traceback
from typing import Awaitable, Callable, NamedTuple, Sequence

import aiohttp

from . import eventloop

LOGGER = logging.getLogger(__name__)


_MESSAGE_FIELDS = {}

def format_type_name(ctype):
    """
    Convert a type or list of types to a string
    """
    if isinstance(ctype, Sequence):
        return '[{}]'.format(', '.join(map(format_type_name, ctype)))
    elif ctype is None:
        return 'None'
    return ctype.__name__

class ExchangeMessage:
    """
    A common base class for exchange messages
    """
    __slots__ = ('_values',)
    _fields = ()

    def __init__(self, *args, **kwargs):
        names, types, defaults, _positions = self._field_specs
        vals = []
        idx = 0
        if len(args) + len(kwargs) > len(names):
            raise TypeError("Too many arguments to constructor")
        for idx, name in enumerate(names):
            ftype = types.get(name)
            if idx < len(args):
                val = args[idx]
            else:
                if name in kwargs:
                    val = kwargs[name]
                elif name in defaults:
                    val = defaults[name]
                else:
                    raise TypeError("Property not provided to constructor: {}".format(name))
            if val is not None and ftype is not None and not isinstance(val, ftype):
                raise TypeError("Incorrect type for property '{}' ({}), expected {}".format(
                    name, format_type_name(type(val)), format_type_name(ftype)))
            vals.append(val)
        self._values = tuple(vals)

    @property
    def _field_specs(self):
        cname = self.__class__.__name__
        if cname not in _MESSAGE_FIELDS:
            names = []
            defaults = {}
            positions = {}
            types = {}
            for idx, field in enumerate(self._fields):
                if isinstance(field, tuple):
                    name = field[0]
                    if len(field) > 1:
                        types[name] = field[1]
                        if len(field) > 2:
                            defaults[name] = field[2]
                else:
                    name = field
                names.append(name)
                positions[name] = idx
            _MESSAGE_FIELDS[cname] = (names, types, defaults, positions)
        return _MESSAGE_FIELDS[cname]

    @property
    def _field_names(self):
        return self._field_specs[0]

    @property
    def _field_types(self):
        return self._field_specs[1]

    @property
    def _field_defaults(self):
        return self._field_specs[2]

    @property
    def _field_positions(self):
        return self._field_specs[3]

    def __iter__(self):
        return ((fname, self[idx]) for (idx, fname) in enumerate(self._field_names))

    def __getattr__(self, name):
        if name in self._field_names:
            return self._values[self._field_positions[name]]
        raise AttributeError("Unknown attribute: {}".format(name))

    def __getitem__(self, key):
        if isinstance(key, (slice, int)):
            return self._values[key]
        return getattr(self, key)

    def get(self, name: str, defval=None):
        """
        Get a property of the message by name

        Args:
            name: the property name
            defval: the default value to return if the property is not defined
        """
        return getattr(self, name, defval)

    def __repr__(self):
        cls = self.__class__.__name__
        params = ['{}={}'.format(fname, self[idx]) for (idx, fname) in enumerate(self._field_names)]
        return '{}({})'.format(cls, ', '.join(params))


class ExchangeFail(ExchangeMessage):
    """
    An error class to represent an exception in message processing

    This is not a subclass of :class:`Exception` as that cannot be pickled
    and transported over the message bus
    """
    _fields = ('value', 'exc_info')
    def __init__(self, value, exc_info=True):
        if exc_info is True:
            # cannot pass real exception or traceback through the message pipe
            exc_info = traceback.format_exc()
        super(ExchangeFail, self).__init__(value, exc_info)

    def format(self) -> str:
        """
        Format this :class:`ExchangeFail` instance as a string including the
        traceback, if any
        """
        ret = '{}'.format(self.value)
        if self.exc_info:
            ret += "\n" + str(self.exc_info)
        return ret

    def __repr__(self):
        cls = self.__class__.__name__
        ret = '{}(value={})'.format(cls, self.value)
        if self.exc_info:
            ret += "\n" + str(self.exc_info)
        return ret


class StopMessage(ExchangeMessage):
    """
    Basic stop-processing message for :class:`MessageProcessor` instances
    """
    pass


MessageWrapper = NamedTuple('MessageWrapper', [
    ('from_pid', str),
    ('ident', str),
    ('message', ExchangeMessage),
    ('ref', str)])
MessageWrapper.__new__.__defaults__ = (None,)
MessageWrapper.__doc__ = """
    A wrapper for a message being passed through the :class:`Exchange` message bus

    Attributes:
        from_pid (str): The identifier of the sending service
        ident (str): A unique identifier for the message, used to tag responses
        message (ExchangeMessage): The message received
        ref (str): An optional identifier for the message being responded to
    """

QueuedMessage = NamedTuple('QueuedMessage', [
    ('to_pid', str),
    ('message', ExchangeMessage)])
QueuedMessage.__doc__ = """
    A wrapper for a message queued to be sent to the exchange

    Attributes:
        to_pid (str): The identifier of the recipient service
        message (ExchangeMessage): The message to be sent
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
        self._proc = None
        self._req_cond = mp.Condition(mp.Lock())

    def start(self, process: bool = True) -> None:
        """
        Start the message exchange as a thread or process
        """
        if process:
            evt = mp.Event()
            proc = mp.Process(target=self._run, args=(evt,))
        else:
            evt = Event()
            proc = Thread(target=self._run, args=(evt,))
        proc.daemon = True
        proc.start()
        evt.wait()
        self._proc = proc
        LOGGER.info('Started exchange')

    def stop(self, drain: bool = True) -> None:
        """
        Send a stop signal to the polling thread
        """
        LOGGER.info('Stopping exchange')
        with self._req_cond:
            self._cmd('stop', drain)
            # wake all threads waiting for an incoming message
            self._req_cond.notify_all()

    def join(self) -> None:
        """
        Wait for the exchange to finish running
        """
        self._proc.join()

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

    def register(self, to_pid: str) -> bool:
        """
        Register a listener on the exchange
        """
        return self._cmd('register', to_pid)

    def is_registered(self, to_pid: str) -> bool:
        """
        Check if a listener is currently running
        """
        return self._cmd('check', to_pid)

    def send(self, to_pid: str, wrapper: MessageWrapper) -> bool:
        """
        Add a message to the bus, blocking until the processing thread is ready

        Args:
            to_pid: The identifier for the receiving service
            wrapper: The message to be added to the queue

        Returns:
            True if the message is successfully added to the queue
        """
        # Blocks until we have access to the message queues and command pipe
        # FIXME add a maximum buffer size for the message queues and allow blocking
        # until there is room in the buffer (optional blocking=True argument)
        with self._req_cond:
            LOGGER.debug('send to %s/%s %s', to_pid, wrapper.ref, wrapper.message)
            status = self._cmd('send', to_pid, wrapper)
            # wake all threads waiting for an incoming message
            self._req_cond.notify_all()
        return status

    def recv(self, to_pid: str, blocking: bool = True, timeout=None) -> MessageWrapper:
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
                while message is None and (blocking or timeout is not None):
                    #LOGGER.warning("Locked (%r), wait", locked)
                    locked = self._req_cond.wait(timeout)
                    if locked:
                        message = self._cmd('recv', to_pid)
                    if not locked or timeout is not None:
                        break
                if locked:
                    self._req_cond.release()
        except Exception:
            LOGGER.exception('Error in recv:')
            raise
        return message

    def _drain(self) -> None:
        while self._cmd('drain'):
            time.sleep(1)

    def _run(self, event: Event) -> None:
        """
        The message processing loop
        """
        drain = Thread(target=self._drain)
        drain.start()
        #pylint: disable=broad-except
        pending = 0
        processed = {}
        queue = {}
        stop_time = None
        event.set()
        try:
            while True:
                command = self._cmd_pipe[0].recv()
                if command[0] == 'register':
                    to_pid = command[1]
                    if to_pid and to_pid not in queue:
                        queue[to_pid] = deque()
                        self._cmd_pipe[0].send(True)
                        LOGGER.debug("registered %s", to_pid)
                    else:
                        self._cmd_pipe[0].send(False)
                elif command[0] == 'check':
                    to_pid = command[1]
                    self._cmd_pipe[0].send(to_pid and to_pid in queue)
                elif command[0] == 'send':
                    if stop_time:
                        LOGGER.debug("rejected message %s %s", command[1], command[2])
                        self._cmd_pipe[0].send(False)
                    else:
                        to_pid = command[1]
                        if to_pid in queue:
                            queue[to_pid].append(command[2])
                            pending += 1
                        else:
                            self._cmd_pipe[0].send(True)
                        self._cmd_pipe[0].send(True)
                elif command[0] == 'recv':
                    to_pid = command[1]
                    wrapper = None
                    if to_pid in queue:
                        try:
                            wrapper = queue[to_pid].popleft()
                            processed[to_pid] = processed.get(to_pid, 0) + 1
                            pending -= 1
                        except IndexError:
                            pass
                        if wrapper and isinstance(wrapper.message, StopMessage):
                            pending -= len(queue[to_pid])
                            del queue[to_pid]
                            LOGGER.debug("unregistered %s", to_pid)
                    self._cmd_pipe[0].send(wrapper)
                elif command[0] == 'status':
                    total = sum(processed.values())
                    self._cmd_pipe[0].send({
                        'pending': pending,
                        'processed': processed,
                        'total': total})
                elif command[0] == 'drain':
                    # clean up expired messages ...
                    if stop_time:
                        if not pending or time.time() - stop_time >= 5:
                            if pending:
                                LOGGER.debug("terminating with %s messages pending", pending)
                            self._cmd_pipe[0].send(False)
                            break
                    self._cmd_pipe[0].send(True)
                elif command[0] == 'stop':
                    for to_pid in queue:
                        LOGGER.debug("ordering %s to stop", to_pid)
                        queue[to_pid].append(MessageWrapper(None, None, StopMessage()))
                        pending += 1
                    stop_time = time.time()
                    self._cmd_pipe[0].send(True)
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

    def _send_message(self, message: MessageWrapper) -> bool:
        """
        Perform the actual addition to the message queue

        Args:
            message: the message to be sent
        """
        return self._exchange.send(self._pid, message)

    def send(
            self,
            ident: str,
            message: ExchangeMessage,
            ref: str = None,
            from_pid: str = None) -> bool:
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
        return self._send_message(MessageWrapper(
            from_pid if from_pid is not None else self._from_pid,
            ident,
            message,
            ref))

    def send_noreply(
            self,
            message: ExchangeMessage,
            ref: str = None,
            from_pid: str = None) -> bool:
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
        self._poll_thread = None

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

    def get_message_target(self, pid: str) -> MessageTarget:
        """
        Quickly create a :class:`MessageTarget` for a service on the same message bus
        """
        return MessageTarget(pid, self._exchange, self._pid)

    def start(self, _wait: bool = True) -> None:
        """
        Run a thread to poll for received messages
        """
        self._poll_thread = Thread(target=self._run)
        self._poll_thread.start()

    def _start_run(self) -> bool:
        """
        Perform any additional initializion in polling thread
        """
        return self._exchange.register(self._pid)

    def join(self) -> None:
        """
        Await our polling thread. `stop()` must be called in order to cause it to abort
        """
        if self._poll_thread:
            self._poll_thread.join()

    def send_stop_message(self) -> bool:
        """
        Send the service a stop signal to end processing
        """
        return self.send_noreply(self._pid, StopMessage())

    def stop(self, wait: bool = True) -> None:
        """
        Send a stop signal to the polling thread in order to abort polling
        """
        if self.send_stop_message():
            while wait and self._exchange.is_registered(self._pid):
                time.sleep(0.01)

    def _stop_run(self) -> None:
        """
        Perform any additional shutdown actions in polling thread
        """
        pass

    def _run(self) -> None:
        """
        The main thread run loop
        """
        if not self._start_run():
            return
        self._poll_messages()
        self._stop_run()

    def _poll_messages(self) -> None:
        """
        The polling loop for receiving messages from the exchange
        """
        #pylint: disable=broad-except
        try:
            while self._poll_message():
                pass
        except Exception:
            LOGGER.exception('Exception while processing messages:')

    def _poll_message(self) -> bool:
        """
        Wait for a message from the exchange
        """
        #pylint: disable=broad-except
        # blocks until a message is available
        received = self._exchange.recv(self._pid)
        LOGGER.debug('%s processing message: %s', self._pid, received.message)
        if isinstance(received.message, StopMessage):
            return False
        try:
            if self._process_message(received) is False:
                return False
        except Exception:
            LOGGER.exception('Exception during message processing:')
            errmsg = ExchangeFail('Exception during message processing', True)
            self._reply_with_error(received, errmsg)
        return True

    def _reply_with_error(
            self,
            from_message: MessageWrapper,
            errmsg: ExchangeFail) -> bool:
        """
        Send an error message back to the sender of a previous message

        Args:
            from_message: the message which triggered the error
            errmsg: the error message to be sent
        """
        if isinstance(from_message.message, ExchangeFail):
            LOGGER.error(from_message.message.format())
            return False
        return self.send_noreply(from_message.from_pid, errmsg, from_message.ident)

    def _send_message(self, to_pid: str, wrapper: MessageWrapper) -> bool:
        """
        Perform the actual addition to the exchange message queue

        Args:
            to_pid: the identifier of the recipient
            message: the message to be sent
        """
        return self._exchange.send(to_pid, wrapper)

    def send(
            self,
            to_pid: str,
            ident: str,
            message: ExchangeMessage,
            ref: str = None,
            from_pid: str = None) -> bool:
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
        return self._send_message(
            to_pid,
            MessageWrapper(from_pid or self._pid, ident, message, ref))

    def send_noreply(
            self,
            to_pid: str,
            message: ExchangeMessage,
            ref: str = None,
            from_pid: str = None) -> bool:
        """
        Send a message with no reply expected

        Returns:
            True if the message was successfully added to the queue
        """
        return self._send_message(
            to_pid,
            MessageWrapper(from_pid or self._pid, None, message, ref))

    def _process_message(self, received: MessageWrapper) -> bool:
        """
        Process a message from another service and optionally send a message in response

        Returns: `False` if the polling thread should terminate
        """
        pass


class LoggingTCPConnector(aiohttp.TCPConnector):
    def _release(self, key, protocol, *, should_close=False):
        close = should_close or self._force_close or protocol.should_close
        LOGGER.debug("Connection released: %s", close and "Closing" or "Leaving open")
        super(LoggingTCPConnector, self)._release(key, protocol, should_close=should_close)


class RequestExecutor(MessageProcessor):
    """
    An subclass of :class:`MessageProcessor` which starts a thread for each outgoing request
    to wait for responses. One of these should live in each process which wants to perform
    async requests via the :class:`Exchange` (like a webserver process). It normally assumes
    that all incoming messages are simply responses to earlier requests.
    Processing should not block the main thread (much) to avoid breaking asyncio.
    """

    def __init__(self, pid: str, exchange: Exchange):
        super(RequestExecutor, self).__init__(pid, exchange)
        self._connector = None
        self._out_queue = None
        self._req_lock = None
        self._requests = {}
        self._runner = None

    def start(self, wait: bool = True) -> None:
        """
        Initialize our :class:`eventloop.Runner` and run our polling thread to listen for messages
        """
        self._out_queue = Queue()
        self._runner = eventloop.Runner()
        self._runner.start(wait)
        self._req_lock = asyncio.Lock(loop=self._runner.loop)
        # Poll for results in a thread from our thread pool
        self.run_thread(self._run, ident='polling thread {}'.format(self.pid))

    def _start_run(self) -> bool:
        if not super(RequestExecutor, self)._start_run():
            return False
        # Send outgoing messages to the exchange (without blocking our event loop)
        self.run_thread(self._send_messages, ident='sending thread {}'.format(self.pid))
        return True

    # In the webserver environment, the process we're concerned with has already started
    # so just use start() instead
    def start_process(self) -> mp.Process:
        """
        Start this executor in a new process
        """
        def _start():
            self._init_process()
            self.start()
            self._runner.join()
        asyncio.get_child_watcher()
        proc = mp.Process(target=_start)
        proc.start()
        return proc

    def runner(self) -> eventloop.Runner:
        """
        Accessor for the event loop runner instance used to execute tasks
        """
        return self._runner

    def _stop_run(self) -> None:
        """
        Stop our sending thread and any other tasks in progress
        """
        # stop sending messages
        self._out_queue.put_nowait(None)
        self._out_queue.join()
        # close TCP connector
        if self._connector:
            self._connector.close()
        # shut down event loop
        self._runner.stop()

    def run_task(self, proc: Awaitable) -> asyncio.Future:
        """
        Add a coroutine task to be performed by the runner

        Args:
            proc: the coroutine to be executed in the runner's event loop
        """
        return self._runner.run_task(proc)

    def run_thread(self, proc: Callable, *args, ident: str = None) -> asyncio.Future:
        """
        Add a task to be processed, as either a coroutine or function

        Args:
            proc: the function to be run in the :class:`ThreadPoolExecutor`
            args: arguments to pass to the proc, if a function
        """
        if ident and False:
            _proc = proc
            def proc(*args):
                tid = get_ident()
                LOGGER.info(">> start thread %s %s", ident, tid)
                ret = _proc(*args)
                LOGGER.info("<< end thread %s %s", ident, tid)
                return ret
        return self._runner.run_in_executor(None, proc, *args)

    def _init_process(self) -> None:
        """
        Initialize ourselves in a newly started process
        """
        # create new event loop after fork
        asyncio.get_event_loop().close()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    def _send_messages(self) -> None:
        """
        Thread loop for sending messages added to the out-queue
        """
        while True:
            msg = self._out_queue.get()
            if msg is None:
                self._out_queue.task_done()
                break
            self._exchange.send(msg.to_pid, msg.message)
            self._out_queue.task_done()

    def _send_message(self, to_pid: str, wrapper: MessageWrapper) -> bool:
        """
        Add the message to our out-queue for processing instead of sending directly

        Args:
            to_pid: the identifier of the recipient
            message: the message to be sent
        """
        self._out_queue.put_nowait(QueuedMessage(to_pid, wrapper))
        return True

    async def _send_request(self, to_pid: str, request: ExchangeMessage,
                            future: Future, timeout: int = None) -> None:
        """
        Send a request to a target service on the exchange and add it to our
        collection to automatically associate the response later

        Args:
            to_pid: the target service identifier
            request: the message payload
            future: used to return the response to (potentially) another thread
            timeout: an optional timeout before cancelling the request
        """
        message = MessageWrapper(self._pid, os.urandom(10), request)
        result = None
        async with self._req_lock:
            if message.ident in self._requests:
                future.set_exception(RuntimeError('Duplicate request identifier'))
                return
            self._requests[message.ident] = future
        result = self._send_message(to_pid, message)
        if not result:
            future.set_exception(RuntimeError('Request could not be processed'))
        elif timeout:
            self.run_task(self._cancel_request(message.ident, timeout))

    async def _cancel_request(self, ident: str, timeout: int = None) -> None:
        """
        Cancel an outstanding request

        Args:
            ident: the request identifier
            timeout: an optional timeout to wait before cancelling
        """
        if timeout:
            await asyncio.sleep(timeout)
        async with self._req_lock:
            if ident in self._requests and not self._requests[ident].done():
                self._requests[ident].cancel()

    def submit(
            self,
            to_pid: str,
            request: ExchangeMessage,
            timeout: int = None) -> asyncio.Future:
        """
        Submit a message to another service and run a task to poll for the results

        Args:
            to_pid: the identifier of the target service
            request: the body of the message to be sent
            timeout: an optional timeout to wait before cancelling the request
        """
        result = Future()
        self.run_task(self._send_request(to_pid, request, result, timeout))
        return asyncio.wrap_future(result)

    async def _handle_message(self, received: MessageWrapper) -> bool:
        """
        Handle a message received from another service on the exchange by awaking
        any tasks waiting for results

        Args:
            received: the received message to be processed
        """
        result = False
        if received.ref:
            async with self._req_lock:
                if received.ref in self._requests:
                    if not self._requests[received.ref].cancelled():
                        self._requests[received.ref].set_result(received.message)
                    result = True
                self._requests = {
                    ident: req for ident, req in self._requests.items() if not req.done()}
        return result

    async def _handle_message_task(self, received: MessageWrapper) -> None:
        """
        Handle message processing within our own event loop

        Args:
            received: the message received from the exchange
        """
        #pylint: disable=broad-except
        try:
            if not await self._handle_message(received):
                LOGGER.debug('unhandled message to %s/%s from %s: %s',
                             self._pid, received.ref, received.from_pid, received.message)
        except Exception:
            errmsg = ExchangeFail('Exception during message processing', True)
            self._reply_with_error(received, errmsg)

    def _process_message(self, received: MessageWrapper) -> bool:
        """
        Handle a message received from another service on the exchange

        Args:
            received: the received message to be processed
        """
        # push the handling of the message into our own event loop
        self.run_task(self._handle_message_task(received))
        return True

    @property
    def tcp_connector(self) -> aiohttp.TCPConnector:
        """
        Return a connection pool associated with this event loop, which allows HTTP
        connection reuse
        """
        if not self._connector:
            force_close = os.getenv('HTTP_FORCE_CLOSE_CONNECTIONS')
            force_close = bool(force_close) and force_close != 'false'
            self._connector = LoggingTCPConnector(force_close=force_close)
        return self._connector

    def http_client(self, *args, **kwargs) -> aiohttp.ClientSession:
        """
        Construct an HTTP client using the shared connection pool
        """
        no_reuse = os.getenv('HTTP_NO_CONNECTOR_REUSE')
        no_reuse = bool(no_reuse) and no_reuse != 'false'
        if 'connector' not in kwargs and not no_reuse:
            kwargs['connector'] = self.tcp_connector
            kwargs['connector_owner'] = False
        keep_cookies = os.getenv('HTTP_PRESERVE_COOKIES')
        keep_cookies = bool(keep_cookies) and keep_cookies != 'false'
        if 'cookie_jar' not in kwargs and not keep_cookies:
            kwargs['cookie_jar'] = aiohttp.DummyCookieJar()
        return aiohttp.ClientSession(*args, **kwargs)

    @property
    def http(self):
        """
        A quick accessor for a default HTTP client instance
        """
        return self.http_client()

    def get_request_target(self, pid: str) -> 'RequestTarget':
        """
        Create a :class:`RequestTarget` for a specific service

        Args:
            pid: the identifer of the target service
        """
        return RequestTarget(self, pid)


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

    def __init__(self, executor: RequestExecutor, pid: str):
        self._executor = executor
        self._pid = pid

    @property
    def pid(self):
        """
        Accessor for the target service identifier
        """
        return self._pid

    @property
    def executor(self):
        """
        Accessor for the :class:`RequestExecutor` instance
        """
        return self._executor

    def request(self, message: ExchangeMessage, timeout: int = None) -> asyncio.Future:
        """
        Send a request to the recipient service, awaiting the response in
        a method defined by the executor

        Args:
            message: The message to be sent
            timeout: An optional timeout for the message response
        """
        return self._executor.submit(
            self.pid,
            message,
            timeout)


class HelloProcessor(MessageProcessor):
    """
    A simple request processor for testing response functionality or stress testing
    """
    def _process_message(self, received: MessageWrapper) -> bool:
        self.send_noreply(received.from_pid,
                          'hello from {} {}'.format(os.getpid(), get_ident()), received.ident)


class ThreadedHelloProcessor(HelloProcessor):
    """
    A threaded request processor for testing delayed, blocking and non-blocking responses
    """
    def __init__(self, pid, exchange, blocking=False, max_workers=5):
        super(ThreadedHelloProcessor, self).__init__(pid, exchange)
        self._blocking = blocking
        self._pool = None
        self._max_workers = max_workers

    def start(self, _wait: bool = True) -> None:
        self._pool = ThreadPoolExecutor(self._max_workers) #thread_name_prefix=self._pid
        self._pool.submit(self._run)

    def start_process(self) -> mp.Process:
        """
        Start this demo processor as a process instead of a thread
        """
        proc = mp.Process(target=lambda: self.start().result())
        proc.start()
        return proc

    def _process_message(self, received: MessageWrapper) -> bool:
        if self._blocking:
            self._delayed_process(received)
        else:
            self._pool.submit(self._delayed_process, received)

    def _delayed_process(self, received: MessageWrapper) -> bool:
        time.sleep(1)
        return super(ThreadedHelloProcessor, self)._process_message(received)


# Testing two workers dividing requests:
# hello = ThreadedHelloProcessor('hello', exchange, blocking=True)
# hello.start_process()
# hello.start_process()
# .. exchange.send('hello', None, None, 'poke') ..
