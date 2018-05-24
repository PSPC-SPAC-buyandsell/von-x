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

import logging
import os
from typing import Mapping

from . import config, exchange as exch, schema

LOGGER = logging.getLogger(__name__)


class ServiceManager:
    def __init__(self, env: Mapping=None):
        self._env = env or {}
        self._exchange = exch.Exchange()
        self._executor_cls = exch.RequestExecutor
        self._proc_locals = {'pid': os.getpid()}
        self._schema_mgr = schema.SchemaManager()
        self._services = {}
        self._services_cfg = None
        self.init_services()

    def init_services(self) -> None:
        """
        Initialize all dependent services
        """
        self.load_schemas()

    def start(self, as_process=True) -> None:
        """
        Start the message processor and any other services
        """
        # Run the message processor
        self._exchange.start(as_process)
        # Run all services
        for _id, service in self._services.items():
            service.start()

    def stop(self) -> None:
        """
        Stop the message processor and any other services
        """
        self._exchange.stop()
        for _id, service in self._services.items():
            service.stop()

    @property
    def env(self) -> dict:
        """
        Accessor for our local environment dict
        """
        return self._env

    @property
    def config_root(self) -> str:
        """
        Accessor for the value of the CONFIG_ROOT setting, defaulting to the current directory
        """
        return self._env.get('CONFIG_ROOT') or os.curdir

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
            self._services_cfg = self.load_config_path('SERVICES_CONFIG_PATH', 'services.yml')
        if self._services_cfg:
            return self._services_cfg.get(section) or {}
        return {}

    def load_schemas(self) -> None:
        """
        Load any standard and custom schemas into our SchemaManager
        """
        std = config.load_config('vonx.config:schemas.yml')
        if std:
            self._schema_mgr.load(std)
        ext = self.load_config_path('SCHEMAS_CONFIG_PATH', 'schemas.yml')
        if ext:
            self._schema_mgr.load(ext)

    @property
    def schema_manager(self) -> schema.SchemaManager:
        """
        Accessor for the SchemaManager defined by this ServiceManager
        """
        return self._schema_mgr

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
        if self._proc_locals['pid'] != pid:
            self._proc_locals = {'pid': pid}
        return self._proc_locals

    @property
    def executor(self) -> exch.RequestExecutor:
        """
        Return a per-process request executor which manages requests
        and polls for results coming from other services.
        Note: this is called for each worker process started by the webserver.
        """
        ploc = self.proc_locals
        if not 'executor' in ploc:
            ident = 'exec-{}'.format(ploc['pid'])
            ploc['executor'] = self._executor_cls(ident, self._exchange)
            ploc['executor'].start()
        return ploc['executor']

    def get_service(self, name: str):
        """
        Fetch a defined service by name

        Args:
            name: the string identifier for the service

        Returns:
            the service instance, or None if not found
        """
        return self._services.get(name)

    def get_endpoint(self, pid: str, loop=None) -> exch.Endpoint:
        """
        Get an endpoint for sending messages to a service on the message exchange.
        Requests will be handled by the executor for this manager in this process.

        Args:
            pid: the identifier for the endpoint on the message bus
            loop: the current event loop, if any
        """
        ploc = self.proc_locals
        name = 'endpt_' + pid
        if name not in ploc:
            ploc[name] = self.executor.get_endpoint(pid)
        if loop:
            ploc[name].loop = loop
        return ploc[name]

    def get_service_endpoint(self, name: str, loop=None) -> exch.Endpoint:
        """
        Get an endpoint for one of the services defined by this manager.
        This Endpoint can be used for sending process-safe messages and receiving results.

        Args:
            name: the string identifier for the service
            loop: the current event loop, if any
        """
        if name in self._services:
            return self.get_endpoint(self._services[name].pid, loop)
        return None
