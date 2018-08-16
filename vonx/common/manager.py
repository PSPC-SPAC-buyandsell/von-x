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
Implemention of the generic :class:`ServiceManager` class which is used to manage
a collection of :class:`ServiceBase` instances
"""


import logging
import os
from typing import Mapping

from . import config
from . import exchange as exch
from .service import (
    ServiceBase,
    ServiceStatus,
    ServiceStatusReq,
    ServiceResponse)

LOGGER = logging.getLogger(__name__)


class ServiceManager(ServiceBase):
    """
    The standard :class:`ServiceManager` class is responsible for starting the
    message exchange, registering itself as a service, starting any dependent
    services, and checking the status of those services. It should normally be run
    with `start_process()` before the web server process has forked.
    """

    def __init__(self, env: Mapping = None, pid: str = "manager"):
        super(ServiceManager, self).__init__(pid, exch.Exchange(), env or {})
        self._executor_cls = exch.RequestExecutor
        self._proc_locals = {"pid": os.getpid()}
        self._services = {}
        self._init_services()

    def _init_services(self) -> None:
        """
        Initialize all dependent services
        """
        pass

    def add_service(self, svc_id: str, service: ServiceBase):
        """
        Add a service to the service manager instance

        Args:
            svc_id: the unique identifier for the service
            service: the service instance
        """
        self._services[svc_id] = service

    async def get_service_status(self, svc_id: str) -> dict:
        """
        Fetch the status of a registered service

        Args:
            svc_id: the unique identifier for the service
        """
        pid = self.get_service(svc_id).pid
        result = await self.executor.submit(pid, ServiceStatusReq())
        if isinstance(result, ServiceStatus):
            return result.status
        else:
            raise RuntimeError("Unexpected response to status request: {}".format(result))

    def start(self, wait: bool = True) -> None:
        """
        Start the message processor and any other services
        """
        self._exchange.start(False)
        super(ServiceManager, self).start(wait)

    async def _service_start(self) -> bool:
        """
        Start all registered services
        """
        for _svc_id, service in self._services.items():
            service.start(True)
        return True

    def stop(self, wait: bool = True) -> None:
        """
        Stop the message processor and any other services
        """
        super(ServiceManager, self).stop(wait)
        self._exchange.stop()

    async def _service_stop(self) -> None:
        """
        Stop all registered services
        """
        LOGGER.debug("Stopping managed services")
        for _id, service in self._services.items():
            service.stop()

    async def _get_status(self) -> ServiceResponse:
        """
        Return the current status of the service
        """
        status = self._status.copy()
        status["services"] = {}
        for svc_id in self._services:
            status["services"][svc_id] = await self.get_service_status(svc_id)
        return ServiceStatus(status)

    @property
    def env(self) -> dict:
        """
        Accessor for our local environment dict
        """
        return self._env

    @property
    def exchange(self) -> exch.Exchange:
        """
        Accessor for the Exchange this ServiceManager uses for messaging
        """
        return self._exchange

    @property
    def proc_locals(self) -> dict:
        """
        Accessor for all process-local variables

        Returns:
            a dictionary of currently-defined variables
        """
        pid = os.getpid()
        if self._proc_locals["pid"] != pid:
            self._proc_locals = {"pid": pid}
        return self._proc_locals

    @property
    def executor(self) -> exch.RequestExecutor:
        """
        Return a per-process request executor which manages requests
        and polls for results coming from other services.
        Note: this is called for each worker process started by the webserver.
        """
        ploc = self.proc_locals
        if not "executor" in ploc:
            ident = "exec-{}".format(ploc["pid"])
            ploc["executor"] = self._executor_cls(ident, self._exchange)
            ploc["executor"].start()
        return ploc["executor"]

    def get_service(self, name: str):
        """
        Fetch a defined service by name

        Args:
            name: the string identifier for the service

        Returns:
            the service instance, or None if not found
        """
        if name == "manager":
            return self
        return self._services.get(name)

    def get_service_message_target(self, name: str) -> exch.MessageTarget:
        """
        Get an endpoint for one of the services defined by this manager.
        This Endpoint can be used for sending process-safe messages and receiving results.

        Args:
            name: the string identifier for the service
            loop: the current event loop, if any
        """
        svc = self.get_service(name)
        if svc:
            return self.executor.get_message_target(svc.pid)
        return None

    def get_service_request_target(self, name: str) -> exch.RequestTarget:
        """
        Get an endpoint for sending messages to a service on the message exchange.
        Requests will be handled by the executor for this manager in this process.

        Args:
            name: the string identifier for the service
            loop: the current event loop, if any
        """
        ploc = self.proc_locals
        tg_name = "target_" + name
        if tg_name not in ploc:
            svc = self.get_service(name)
            if svc:
                ploc[tg_name] = self.executor.get_request_target(svc.pid)
            else:
                return None
        return ploc[tg_name]


class ConfigServiceManager(ServiceManager):
    """
    A :class:`ServiceManager` subclass with standard configuration loading methods
    """

    def __init__(self, env: Mapping = None, pid: str = "manager"):
        super(ConfigServiceManager, self).__init__(env, pid)
        self._services_cfg = None

    @property
    def config_root(self) -> str:
        """
        Accessor for the value of the CONFIG_ROOT setting, defaulting to the current directory
        """
        return self._env.get("CONFIG_ROOT") or os.curdir

    def load_config_path(self, settings_key, default_path, env=None) -> dict:
        """
        Load a YAML configuration file with defined variables replaced in the result

        Args:
            settings_key: the name of an environment variable defining an alternative
                configuration path
            default_path: the default path to the configuration file

        Returns:
            the parsed YAML configuration with variables replaced
        """
        path = self._env.get(settings_key)
        if not path:
            path = os.path.join(self.config_root, default_path)
        return config.load_config(path, env or self._env)

    def services_config(self, section: str) -> dict:
        """
        Load a named section from the global services.yml configuration

        Args:
            section: the configuration key
        """
        if self._services_cfg is None:
            self._services_cfg = self.load_config_path("SERVICES_CONFIG_PATH", "services.yml")
        if self._services_cfg:
            return self._services_cfg.get(section) or {}
        return {}
