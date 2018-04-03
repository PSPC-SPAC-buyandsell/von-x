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

from . import config, exchange, schema

LOGGER = logging.getLogger(__name__)


class ServiceManager:
    def __init__(self, env):
        self._env = env
        self._exchange = exchange.Exchange()
        self._executor_cls = exchange.RequestExecutor
        self._proc_locals = {'pid': os.getpid()}
        self._schema_mgr = schema.SchemaManager()
        self._services = {}
        self._services_cfg = None
        self.init_services()

    def init_services(self):
        self.load_schemas()

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
    def config_root(self):
        return self._env.get('CONFIG_ROOT') or os.curdir

    def load_config_path(self, settings_key, default_path, env=None) -> dict:
        path = self._env.get(settings_key)
        if not path:
            path = os.path.join(self.config_root, default_path)
        return config.load_config(path, env or self._env)

    def services_config(self, section) -> dict:
        if self._services_cfg is None:
            self._services_cfg = self.load_config_path('SERVICES_CONFIG_PATH', 'services.yml')
        if self._services_cfg:
            return self._services_cfg.get(section) or {}
        return {}

    def load_schemas(self):
        std = config.load_config('app.config:schemas.yml')
        if std:
            self._schema_mgr.load(std)
        ext = self.load_config_path('SCHEMAS_CONFIG_PATH', 'schemas.yml')
        if ext:
            self._schema_mgr.load(ext)

    @property
    def schema_manager(self):
        return self._schema_mgr

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

    def get_endpoint(self, pid: str, loop=None):
        ploc = self.proc_locals
        name = 'endpt_' + pid
        if name not in ploc:
            ploc[name] = self.executor.get_endpoint(pid)
        if loop:
            ploc[name].set_async_loop(loop)
        return ploc[name]

    def get_service_endpoint(self, name: str, loop=None):
        if name in self._services:
            return self.get_endpoint(self._services[name].pid, loop)
        return None
