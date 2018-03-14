from concurrent.futures import Executor, Future
from collections import deque
import logging
import multiprocessing
from queue import Queue, Empty
import threading
import time
logger = logging.getLogger(__name__)


REQUEST_STATUS = 'status'

class Request:
    def __init__(self, action=None, value=None, ident=None):
        self.action = action
        self.value = value
        self.ident = ident or {}
    def encode(self):
        return {'ident': self.ident, 'action': self.action, 'value': self.value}
    def __str__(self):
        return 'Request(action={},value={},ident={})'.format(
            self.action, self.value, self.ident)

class Response:
    def __init__(self, ident=None, action=None, value=None, exception=None):
        self.ident = ident
        self.action = action
        self.value = value
        self.exception = exception
    def encode(self):
        return {'ident': self.ident, 'action': self.action, 'value': self.value, 'exception': self.exception}
    def __str__(self):
        return 'Response(action={},value={},exception={},ident={})'.format(
            self.action, self.value, self.exception, self.ident)


class Exchange:
    """
        Collect queued results for different client processes and allow them
        to be fetched
    """
    def __init__(self):
        self._lock = multiprocessing.Lock()
        self._pipe = multiprocessing.Pipe()

    def start(self):
        self._queues = {}
        self._poll = multiprocessing.Process(target=self._run_loop)
        self._poll.start()

    def stop(self):
        return self.process('stop')

    def fetch(self, exec_id):
        return self.process('fetch', exec_id)

    def append(self, exec_id, value):
        return self.process('append', (exec_id, value))

    def append_all(self, value):
        return self.process('append_all', value)

    def register(self):
        return self.process('register')

    def process(self, action, value=None):
        self._lock.acquire()
        ret = None
        try:
            self._pipe[0].send( (action, value) )
            ret = self._pipe[0].recv()
        finally:
            self._lock.release()
        return ret

    def _run_loop(self):
        try:
            pipe = self._pipe[1]
            while True:
                (action, value) = pipe.recv()
                if action == 'stop':
                    pipe.send(None)
                    break
                elif action == 'register':
                    queue = deque()
                    exec_id = id(queue)
                    self._queues[exec_id] = queue
                    pipe.send(exec_id)
                elif action == 'append':
                    (exec_id, response) = value
                    if exec_id in self._queues:
                        self._queues[exec_id].append(response)
                        pipe.send(True)
                    else:
                        pipe.send(False)
                elif action == 'append_all':
                    for exec_id, queue in self._queues.items():
                        queue.append(value)
                    pipe.send(True)
                elif action == 'fetch':
                    if value in self._queues:
                        queue = self._queues[value]
                        ret = queue.popleft() if len(queue) else None
                        pipe.send(ret)
                    else:
                        logger.debug('listener not defined {}'.format(value))
                        pipe.send(None)
                else:
                    logger.error('Unrecognized command for exchange: {}'.format(action))
                    pipe.send(None)
        except:
            logger.exception('Error in exchange loop:')


class RequestProcessor:
    """
        Handle inputs and distribute to the appropriate handler.
        This will normally run in a separate process.
    """
    def __init__(self):
        self._input_queue = multiprocessing.Queue()
        self._exchange = Exchange()

    def start_process(self):
        logger.debug('Start process')
        def init():
            #loop = asyncio.new_event_loop()
            #asyncio.set_event_loop(loop)
            t1 = self.start()
            t1.join()
        p1 = multiprocessing.Process(target=init)
        p1.start()

    def start(self):
        self._exchange.start()
        t1 = threading.Thread(target=self._input_loop)
        t1.daemon = True
        t1.start()
        self._start_services()
        return t1

    # This may be called in a separate process so we must use the input queue
    def add_executor(self):
        return self._exchange.register()

    def get_output(self, exec_id):
        return self._exchange.fetch(exec_id)

    def stop(self):
        logger.debug('Stopping request processor')
        self._stop_services()
        self._input_queue.put(None)
        self._exchange.stop()

    def send_input(self, request : Request):
        self._input_queue.put(request)

    def ready(self):
        return True

    def _start_services(self):
        pass

    def _stop_services(self):
        pass

    def _send_output(self, response : Response):
        try:
            logger.debug('sending response {}'.format(response))
            if response.ident:
                # send to specific executors
                exec_id = response.ident.get('exec_id')
                if not self._exchange.append(exec_id, response.encode()):
                    logger.error('Executor not found for request ({})'.format(exec_id))
            else:
                # send to all executors
                self._exchange.append_all(response.encode())
        except:
            logger.exception('Exception while sending response:')

    def _input_loop(self):
        # This thread should be safe to block as it's running in the separate process
        logger.debug('in input loop')
        try:
            while True:
                if not self._input_queue.empty():
                    try:
                        request = self._input_queue.get_nowait()
                    except Empty:
                        continue
                    if not request:
                        break
                    logger.debug('got request {}'.format(request))
                    if not self._handle_request(request):
                        logger.error('unrecognized request {}'.format(request))
                time.sleep(0.001)
        except:
            logger.exception('Exception during input loop:')

    def _handle_request(self, request : Request):
        pass


class RequestExecutor(Executor):
    """
        Handle outputs and return to the requesting thread.
        This will run in the web server process(es).
    """
    def __init__(self, processor : RequestProcessor):
        self._requests = []
        self._processor = processor
        self._id = self._processor.add_executor()
        self._poll = threading.Thread(target=self._output_loop)
        self._poll.daemon = True
        self._poll.start()
        self._status = {'ready': False}
        logger.debug('Registered executor {}'.format(self._id))

    def shutdown(self, wait=True):
        # wait not yet implemented, see map method in concurrent/futures/_base.py for example
        self._poll.stop()

    def ready(self):
        return self._status['ready']

    def status(self):
        return self._status

    def submit(self, request : Request) -> Future:
        # should the queue have a maximum size?
        # web server should likely block the request if it's full
        future = Future()
        req_id = id(future)
        self._requests.append(future)
        request.ident['exec_id'] = self._id
        request.ident['request_id'] = req_id
        self._processor.send_input(request)
        return future

    def _output_loop(self):
        logger.debug('in output loop')
        try:
            while True:
                message = self._processor.get_output(self._id)
                if message:
                    response = Response(**message)
                    logger.debug('got response {}'.format(message))
                    if not self._handle_response(response):
                        logger.warning('unrecognized response {}'.format(response))
                time.sleep(0.001)
        except:
            logger.exception('Exception in output loop:')

    def _handle_response(self, response : Response):
        if response.action == 'status':
            self._status = response.value
            return True
        elif response.ident:
            request_id = response.ident.get('request_id')
            if not request_id:
                return
            handled = False
            remain = []
            for future in self._requests:
                if future.cancelled():
                    logger.debug('Cannot return result - future cancelled')
                    if id(future) == request_id:
                        handled = True
                    continue
                if id(future) == request_id:
                    if response.exception:
                        future.set_exception(response.exception)
                    else:
                        future.set_result(response.value)
                    handled = True
                else:
                    remain.append(future)
            self._requests = remain
            return handled

