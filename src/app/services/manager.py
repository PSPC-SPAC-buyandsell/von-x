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

import aiohttp

from . import exchange
from .config import expand_tree_variables

LOGGER = logging.getLogger(__name__)


class ServiceManager:
    def __init__(self, env, config):
        self._env = env
        self._config = config
        self._exchange = exchange.Exchange()
        self._services = {}
        self._proc_locals = {'pid': os.getpid()}
        self._executor_cls = exchange.RequestExecutor
        self.init_services()

    def init_services(self):
        pass

    def start(self, as_process=True):
        # Run the message processor
        self._exchange.start(as_process)
        # Run all services
        for _id, service in self._services.items():
            service.start()

    def stop(self):
        self._exchange.stop()
        for _id, service in self._services.items():
            service.stop()

    @property
    def env(self) -> dict:
        return self._env

    @property
    def config(self) -> dict:
        return self._config

    def expand_config(self, key) -> dict:
        vals = self._config.get(key) or {}
        vals = expand_tree_variables(vals, self._env)
        return vals

    @property
    def exchange(self) -> exchange.Exchange:
        return self._exchange

    @property
    def proc_locals(self) -> dict:
        """
        Process-local variables
        """
        pid = os.getpid()
        if self._proc_locals['pid'] != pid:
            self._proc_locals = {'pid': pid}
        return self._proc_locals

    @property
    def tcp_connection_pool(self):
        """
        Return a process-level connection pool which allows HTTP session reuse
        """
        ploc = self.proc_locals
        if not 'conn_pool' in ploc:
            ploc['conn_pool'] = aiohttp.TCPConnector()
        return ploc['conn_pool']

    def http_client(self, *args, **kwargs):
        """
        Construct an HTTP client using the shared connection pool
        """
        kwargs['connector'] = self.tcp_connection_pool
        return KeepAliveClientSession(aiohttp.ClientSession(*args, **kwargs))

    @property
    def executor(self):
        """
        Return a per-process request executor which manages requests
        and polls for results coming from other services.
        Note: this part happens for each worker process started by the webserver.
        FIXME - allow executor class to be changed, may depend on the webserver
        """
        ploc = self.proc_locals
        if not 'executor' in ploc:
            ident = 'exec-{}'.format(ploc['pid'])
            ploc['executor'] = self._executor_cls(ident, self._exchange)
            ploc['executor'].start()
        return ploc['executor']

    def get_service(self, name: str):
        return self._services[name]

    def get_endpoint(self, pid: str, async_loop=None):
        locals = self.proc_locals
        name = 'endpt_' + pid
        if name not in locals:
            locals[name] = self.executor.get_endpoint(pid)
        locals[name].set_async_loop(async_loop)
        return locals[name]

    def get_service_endpoint(self, name: str, async_loop=None):
        if name in self._services:
            return self.get_endpoint(self._services[name].get_pid(), async_loop)


class KeepAliveClientSession:
    """
    A simple wrapper to leave HTTP sessions open.
    This allows the connection pool to take advantage of keepalive (and avoids errors)
    """
    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            LOGGER.exception('Exception in HTTP client:')
