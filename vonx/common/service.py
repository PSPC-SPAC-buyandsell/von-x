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
import logging
from typing import Mapping

from .exchange import (
    Exchange,
    ExchangeFail,
    ExchangeMessage,
    MessageWrapper,
    RequestExecutor)

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
    _fields = (
        ('status', dict),
    )
    """
    Request the status of a service
    """

class ServiceSyncReq(ServiceRequest):
    """
    Request a service to perform a sync
    """
    pass

class ServiceSyncError(Exception):
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
            "started": False
        }
        self._sync_lock = None

    def start(self, wait: bool = True) -> None:
        """
        Start the IssuerManager processing thread and related services
        """
        super(ServiceBase, self).start()
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

    async def _sync(self) -> None:
        """
        Service sync process
        """
        #pylint: disable=broad-except
        async with self._sync_lock:
            if self._status["failed"]:
                return
            prev = self._status["synced"]
            failed = False
            self._update_status(syncing=True)
            if not prev:
                LOGGER.info("Starting sync: %s", self.pid)
            try:
                synced = await self._service_sync()
            except ServiceSyncError:
                LOGGER.exception("Error during %s sync: ", self.pid)
                synced = False
            except Exception as e:
                LOGGER.exception("Fatal error during %s sync: ", self.pid)
                synced = False
                failed = True
            self._update_status(synced=synced, syncing=False, failed=failed)
            if synced and not prev:
                LOGGER.info("Completed sync: %s", self.pid)

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
        return ServiceStatus(self._status.copy())

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

        elif isinstance(request, ServiceSyncReq):
            self.run_task(self._sync())
            reply = ServiceAck()

        elif isinstance(request, ServiceStatusReq):
            reply = await self._get_status()

        elif isinstance(request, ServiceRequest):
            try:
                reply = await self._service_request(request)
            except Exception:
                LOGGER.exception("Exception while handling request:")
                reply = ExchangeFail("Exception while handling request")
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
        pass

    async def _service_response(self, response: ServiceResponse) -> bool:
        pass
