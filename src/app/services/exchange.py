import asyncio
import collections
from concurrent.futures import ThreadPoolExecutor
import logging
import multiprocessing as mp
import os
from threading import Condition, Lock, Thread, get_ident
import sys
import time
import traceback
logger = logging.getLogger(__name__)


class ExchangeError:
    def __init__(self, value, exc_info=None):
        self.value = value
        if exc_info == True:
            # cannot pass real exception or traceback through the pipe
            exc_info = traceback.format_exc()
        self.exc_info = exc_info
    def format(self):
        ret = '{}'.format(self.value)
        if self.exc_info:
            ret += "\n" + str(self.exc_info)
        return ret


# Receive requests and pass them to processors which may live in
# a different process, but have a known identifier. One or more
# processors may respond to the same identifier.
# Responses are optional and can be tied to the original request.
class Exchange:
    def __init__(self):
        self._cmd_pipe = mp.Pipe()
        self._cmd_lock = mp.Lock()
        self._req_cond = mp.Condition(mp.Lock())

    def start(self, process=True):
        if process:
            runner = mp.Process(target=self.run)
        else:
            runner = Thread(target=self.run)
        runner.start()
        return runner

    def stop(self):
        with self._req_cond:
            return self._cmd('stop')

    def status(self):
        with self._req_cond:
            return self._cmd('status')

    def _cmd(self, *command):
        with self._cmd_lock:
            # ensure that each command send has a corresponding recv
            self._cmd_pipe[1].send(command)
            return self._cmd_pipe[1].recv()

    def send(self, to_pid, from_pid, ident, message, ref=None):
        #logger.debug('get cond send')
        with self._req_cond:
            #logger.debug('in cond send')
            # blocks until we have access to the command pipe and the queue
            # if the queue gets a maximum buffer size, then we may want to block
            # until there is room in the buffer (blocking=True)
            logger.debug('> send to {}/{} {}'.format(to_pid, ref, message))
            status = self._cmd('send', to_pid, (from_pid, ident, message, ref))
            logger.debug('< send {}'.format(status))
            # wake all threads waiting for an incoming message
            #logger.debug('notify recv')
            self._req_cond.notify_all()
            #logger.debug('release cond recv')
        return status

    def recv(self, to_pid, blocking=True, timeout=None):
        try:
            logger.debug('> recv {}'.format(to_pid))
            #logger.debug('get cond recv')
            locked = self._req_cond.acquire(blocking)
            message = None
            if locked:
                #logger.debug('in cond recv')
                message = self._cmd('recv', to_pid)
                while message == None and (blocking or timeout != None):
                    #logger.debug('sleep {} recv'.format(to_pid))
                    locked = self._req_cond.wait(timeout)
                    #logger.debug('wake {} recv {}'.format(to_pid, locked))
                    if locked:
                        message = self._cmd('recv', to_pid)
                    #logger.debug('got {} {}'.format(to_pid, message))
                    if not locked or message != None or timeout != None:
                        break
                #logger.debug('release cond recv')
                if locked:
                    self._req_cond.release()
                #logger.debug('released {}'.format(self._req_cond))
            logger.debug('< recv {} {}'.format(to_pid, message))
        except:
            logger.exception('Error in recv:')
            raise
        return message

    def run(self):
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
                    # cond must be acquired externally
                    to_pid = command[1]
                    message = None
                    if to_pid in queue:
                        try:
                            message = queue[to_pid].popleft()
                            processed[to_pid] = processed.get(to_pid, 0) + 1
                            pending -= 1
                        except IndexError:
                            pass
                    # clean up expired requests here?
                    # would want to return a message to the sender that the
                    # message couldn't be delivered
                    self._cmd_pipe[0].send(message)
                elif command[0] == 'status':
                    total = sum(processed.values())
                    self._cmd_pipe[0].send({'pending': pending, 'processed': processed, 'total': total})
                elif command[0] == 'stop':
                    # maybe block new requests and wait until remaining
                    # messages are processed?
                    self._cmd_pipe[0].send(True)
                    break
                else:
                    raise ValueError('Unrecognized command: {}'.format(command[0]))
        except:
            logger.exception('Error in exchange:')



# Polls the exchange for messages sent to this processor
# and runs the 'process' method (must be customized)
class RequestProcessor:
    def __init__(self, pid, exchange : Exchange):
        self._pid = pid
        self._exchange = exchange

    def get_pid(self):
        return self._pid

    def get_exchange(self):
        return self._exchange

    def start(self):
        # FIXME start exchange here if it's not running? need to track running status
        th = Thread(target=self.run)
        th.start()
        return th

    def run(self):
        try:
            while True:
                from_pid, ident, message, ref = self._exchange.recv(self._pid)
                logger.debug('got message {} {}'.format(self._pid, message))
                # FIXME catch exception here and return it to the sender
                try:
                    if self.process(from_pid, ident, message, ref) == False:
                        break
                except:
                    if isinstance(message, ExchangeError):
                        logger.error(message.format())
                    else:
                        errmsg = ExchangeError('Exception during message processing', True)
                        self.send_noreply(from_pid, errmsg, ident)
        except:
            logger.exception('Exception while processing message:')

    def send(self, to_pid, ident, message, ref=None, from_pid=None):
        return self._exchange.send(to_pid, from_pid or self._pid, ident, message, ref)

    def send_noreply(self, to_pid, message, ref=None, from_pid=None):
        return self._exchange.send(to_pid, from_pid or self._pid, None, message, ref)

    def process(self, from_pid, ident, message, ref):
        pass


# One of these should live in each process which wants to perform async
# requests via the Exchange (like a webserver process). It assumes that
# all incoming messages are simply responses to earlier requests.
# Designed to run without blocking the current thread (too much).
class RequestExecutor(RequestProcessor):
    def __init__(self, pid, exchange : Exchange, max_workers=10):
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
            if async_loop == True:
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
                logger.debug('unhandled message to {}/{} from {}: {}'.format(self._pid, ref, from_pid, message))

    def _receive(self, ident, timeout=None):
        with self._req_cond:
            ret = None
            if ident in self._requests:
                ret = self._requests[ident]['result']
                while ret == None:
                    self._req_cond.wait(timeout)
                    if ident not in self._requests:
                        logger.debug('Ident not found in requests')
                        break
                    ret = self._requests[ident]['result']
                    if ret != None or timeout != None:
                        break
            else:
                logger.debug('Ident not found in requests')
            del self._requests[ident]
        return ret


# Wrapper for sending to a single target
# ie. manager = Endpoint(manager_pid, exchange, my_pid)
# _ = manager.send_noreply('hello')
class Endpoint:
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
            from_pid or self._from_pid,
            ident,
            message,
            ref)
    def send_noreply(self, message, ref, from_pid=None):
        return self.send(None, message, ref, from_pid)


# Simple processor for testing responses
class HelloProcessor(RequestProcessor):
    def __init__(self, pid, exchange):
        super(HelloProcessor, self).__init__(pid, exchange)
    def start(self):
        return super(HelloProcessor, self).start()
    def process(self, from_pid, ident, message, ref):
        self.send_noreply(from_pid, 'hello from {} {}'.format(os.getpid(), get_ident()), ident)

# More complicated processor for testing delayed, blocking and non-blocking responses
class ThreadedHelloProcessor(HelloProcessor):
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
    def process(self, *message):
        if self._blocking:
            self._delayed_process(message)
        else:
            self._pool.submit(self._delayed_process, message)
    def _delayed_process(self, message):
        time.sleep(1)
        return super(ThreadedHelloProcessor, self).process(*message)

# Test two workers dividing requests:
# hello = ThreadedHelloProcessor('hello', exchange, blocking=True)
# hello.start_process()
# hello.start_process()
# .. exchange.send('hello', None, None, 'poke') ..

