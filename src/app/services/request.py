from concurrent.futures import Executor, Future
import logging
import multiprocessing
from queue import Empty
import threading
import time
logger = logging.getLogger(__name__)


class Request:
    def __init__(self):
        self.ident = {}

class Response:
    pass

class RequestResponse(Response):
    def __init__(self, ident, value=None, exception=None):
        self.ident = ident
        self.value = value
        self.exception = exception

class StatusResponse(Response):
    def __init__(self, value):
        self.value = value


class RequestProcessor:
    """
        Handle inputs and distribute to the appropriate handler.
        This will normally run in a separate process.
    """
    def __init__(self):
        self._input_queue = multiprocessing.Queue()
        self._output_queue = multiprocessing.Queue()

    def start_process(self):
        def init():
            #loop = asyncio.new_event_loop()
            #asyncio.set_event_loop(loop)
            t1 = self.start()
            t1.join()
        p1 = multiprocessing.Process(target=init)
        p1.start()

    def start(self):
        t1 = threading.Thread(target=self._input_loop)
        t1.daemon = True
        t1.start()
        self._run_services()
        return t1

    #def stop(self):
    #    self._poll and self._poll.stop()
    #    self._poll = None

    def get_output(self):
        try:
            ret = self._output_queue.get_nowait()
            return ret
        except Empty:
            return

    def send_input(self, request : Request):
        self._input_queue.put(request)

    def ready(self):
        return True

    def _run_services(self):
        pass

    def _handle_request(self, request : Request):
        # Should determine handler and return non-empty value
        pass

    def _send_output(self, response : Response):
        self._output_queue.put(response)

    def _input_loop(self):
        # This thread should be safe to block as it's running in the separate process
        logger.debug('in input loop')
        while True:
            request = self._input_queue.get()
            logger.debug('got request {}'.format(request))
            if not self._handle_request(request):
                logger.error('unrecognized request {}'.format(request))


class RequestExecutor(Executor):
    """
        Handle outputs and return to the requesting thread.
        This will run in the application process.
    """
    def __init__(self, processor : RequestProcessor):
        self._requests = []
        self._processor = processor
        self._poll = threading.Thread(target=self._output_loop)
        self._poll.daemon = True
        self._poll.start()
        self._status = {'ready': False}

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
        request.ident['request_id'] = req_id
        self._processor.send_input(request)
        return future

    def _output_loop(self):
        logger.debug('in output loop')
        while True:
            response = self._processor.get_output()
            if response:
                logger.debug('got response {}'.format(response))
                if not self._handle_response(response):
                    logger.warning('unrecognized response {}'.format(response))
            time.sleep(0.001)

    def _handle_response(self, response : Response):
        if isinstance(response, StatusResponse):
            self._status = response.value
            return True
        elif isinstance(response, RequestResponse):
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

