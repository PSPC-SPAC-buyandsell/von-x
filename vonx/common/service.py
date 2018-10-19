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
Basic implementation and message classes for services running on the exchange
"""

import asyncio
import logging
from typing import Mapping

from .exchange import (
    Exchange,
    ExchangeFail,
    ExchangeMessage,
    MessageWrapper,
    RequestExecutor)
from .util import Stats

LOGGER = logging.getLogger(__name__)


class ServiceRequest(ExchangeMessage):
    """
    A standard base class for requests to a service
    """
    pass

class ServiceResponse(ExchangeMessage):
    """
    A standard base class for responses from a service
    """
    pass

class ServiceAck(ServiceResponse):
    """
    A simple acknowledgment response
    """
    pass

class ServiceFail(ExchangeFail):
    """
    A standard base class for errors returned from a service
    """
    pass

class ServiceStatusReq(ServiceRequest):
    """
    Request the status of a service
    """
    pass

class ServiceStatus(ServiceResponse):
    """
    Request the status of a service
    """
    _fields = (
        ("status", dict),
    )

class ServiceStopReq(ServiceRequest):
    """
    Request a service to stop running
    """
    pass

class ServiceSyncReq(ServiceRequest):
    """
    Request a service to perform a sync
    """
    _fields = (
        ("wait", bool),
    )

class ServiceSyncError(Exception):
    """
    An exception raised in response to a controlled failure during synchronization
    """
    pass


class ServiceBase(RequestExecutor):
    """
    The base class for services handled by the :class:`ServiceManager` instance
    """

    def __init__(self, pid: str, exchange: Exchange, env: Mapping):
        super(ServiceBase, self).__init__(pid, exchange)
        self._env = env
        self._status = {
            "id": self._pid,
            "failed": False,
            "synced": False,
            "syncing": False,
            "started": False,
        }
        self._stats = Stats()
        self._sync_again = False
        self._sync_lock = None

    def start(self, wait: bool = True) -> None:
        """
        Start the processing thread and any related services
        """
        super(ServiceBase, self).start(True)
        self._sync_lock = asyncio.Lock(loop=self._runner.loop)
        self.run_task(self._start())

    def _update_status(self, **params) -> None:
        self._status.update(params)

    async def _start(self) -> None:
        """
        Initial service startup
        """
        if await self._service_start():
            self._update_status(started=True)
            LOGGER.info("Started service: %s", self.pid)
            self.run_task(self._sync())

    async def _service_start(self) -> bool:
        """
        Perform service-specific startup actions
        """
        return True

    def send_stop_message(self) -> bool:
        return self.send_noreply(self._pid, ServiceStopReq())

    async def _stop(self) -> None:
        """
        Service shutdown
        """
        async with self._sync_lock:
            await self._service_stop()
            self._update_status(started=False)
        LOGGER.info("Stopped service: %s", self.pid)

    async def _service_stop(self) -> None:
        """
        Perform service-specific shutdown actions
        """
        pass

    async def _sync(self) -> None:
        """
        Service sync process
        """
        #pylint: disable=broad-except
        async with self._sync_lock:
            if not self._status["started"] or self._status["failed"]:
                return
            prev = self._status["synced"]
            if not prev:
                LOGGER.info("Starting sync: %s", self.pid)
            again = True
            failed = False
            synced = False
            while again:
                self._sync_again = again = False
                self._update_status(syncing=True)
                try:
                    synced = await self._service_sync()
                    if self._sync_again:
                        synced = False
                        again = True
                except ServiceSyncError:
                    LOGGER.exception("Error during %s sync: ", self.pid)
                    synced = False
                except Exception:
                    LOGGER.exception("Fatal error during %s sync: ", self.pid)
                    synced = False
                    failed = True
                self._update_status(synced=synced, syncing=False, failed=failed)
            if synced and not prev:
                LOGGER.info("Completed sync: %s", self.pid)

    def _sync_required(self) -> None:
        self._sync_again = True
        self._update_status(synced=False)

    async def _service_sync(self) -> bool:
        """
        Perform service-specific sync actions. This may be called multiple times,
        and should not repeat sync actions that aren't necessary
        """
        return True

    async def _get_status(self) -> ServiceResponse:
        """
        Return the current status of the service
        """
        result = self._status.copy()
        result["stats"] = self._stats.results()
        return ServiceStatus(result)

    async def _handle_message(self, received: MessageWrapper) -> bool:
        """
        Process a message from the exchange and send the reply, if any

        Args:
            received: The message to be processed
        """
        #pylint: disable=broad-except
        from_pid, request, ident = (
            received.from_pid,
            received.message,
            received.ident,
        )

        if await super(ServiceBase, self)._handle_message(received):
            return True

        elif isinstance(request, ServiceStopReq):
            # run service shutdown in async thread
            await self._stop()
            # finish polling
            super(ServiceBase, self).send_stop_message()
            return True

        elif isinstance(request, ServiceSyncReq):
            if request.wait:
                while True:
                    if self._status["failed"]:
                        reply = ServiceFail("Service could not be synced: {}".format(self.pid))
                        break
                    await self._sync()
                    if self._status["synced"]:
                        reply = ServiceAck()
                        break
                    await asyncio.sleep(2)
            else:
                self.run_task(self._sync())
                reply = ServiceAck()

        elif isinstance(request, ServiceStatusReq):
            reply = await self._get_status()

        elif isinstance(request, ServiceRequest):
            try:
                reply = await self._service_request(request)
            except Exception:
                LOGGER.exception("Exception while handling request:")
                reply = ServiceFail("Exception while handling request")
            if reply is None:
                raise ValueError(
                    "Unexpected message from {}: {}".format(from_pid, request)
                )

        elif isinstance(request, ServiceResponse):
            ok = await self._service_response(request)
            if not ok:
                raise ValueError(
                    "Unexpected message from {}: {}".format(from_pid, request)
                )
            return True

        self.send_noreply(from_pid, reply, ident)
        return True

    async def _service_request(self, request: ServiceRequest) -> ServiceResponse:
        """
        Handle a request from another service
        """
        pass

    async def _service_response(self, response: ServiceResponse) -> bool:
        """
        Handle a response from another service
        """
        pass

    def _timer(self, *tasks, log_as=None):
        """
        Start a new timer for a set of tasks
        """
        return self._stats.timer(*tasks, log_as=log_as)
