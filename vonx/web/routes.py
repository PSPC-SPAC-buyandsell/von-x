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
from typing import Coroutine

from aiohttp import web, ClientRequest

from vonx.services.manager import ServiceManager
from . import views
from .process import process_form
from .proxy import proxy_handler
from .render import render_form

LOGGER = logging.getLogger(__name__)


def get_standard_routes(_app) -> list:
    """
    Get the standard list of routes for the von-x application
    """
    return [
        web.get('/', views.index),
        web.get('/health', views.health),
        web.get('/status', views.status),
        web.get('/ledger-status', views.ledger_status),
        #web.post('/construct-proof', views.construct_proof),
        #web.post('/issue-credential', views.issue_credential),
        #web.get('/hello', views.hello),
    ]


def get_custom_routes(app: web.Application) -> list:
    """
    Get the list of routes defined by the application route settings
    """
    return RouteDefinitions.load(app['manager']).routes


def get_routes(app: web.Application) -> list:
    """
    Get the full list of defined routes
    """
    return get_standard_routes(app) + get_custom_routes(app)


class RouteDefinitions:
    """
    Manager class for loading and inspecting the application routing configuration
    """
    def __init__(self):
        self.forms = []
        self.issuers = []
        self.paths = []
        self.proxies = []
        self.static = []

    @classmethod
    def load(cls, manager: ServiceManager) -> 'RouteDefinitions':
        """
        Return a new instance initialized by a :class:`ServiceManager`
        """
        inst = RouteDefinitions()
        inst.load_config(manager)
        return inst

    def add_paths(self, *paths, overwrite: bool = False) -> None:
        """
        Add a list of paths to the defined routes

        Args:
            paths: one or more paths to add
            overwrite: whether to replace an existing path
        """
        for path in paths:
            if self.path_defined(path):
                if not overwrite:
                    raise RuntimeError('Duplicate view path defined: {}'.format(path))
            else:
                self.paths.append(path)

    def add_form(self, form: dict) -> None:
        """
        Add a form route definition

        Args:
            form: a dictionary of form configuration parameters
        """
        self.add_paths(form['path'])
        self.forms.append(form)

    def add_issuer(self, issuer: dict) -> None:
        """
        Add an issuer route definition

        Args:
            issuer: a dictionary of issuer configuration parameters
        """
        self.add_paths(issuer['path'])
        self.issuers.append(issuer)

    def add_proxy(self, proxy: dict) -> None:
        """
        Add a proxy route definition

        Args:
            proxy: a dictionary of proxy configuration parameters
        """
        self.add_paths(proxy['path'])
        self.proxies.append(proxy)

    def add_static(self, static: dict) -> None:
        """
        Add a static resource route definition

        Args:
            static: a dictionary of static resource configuration parameters
        """
        self.add_paths(static['path'])
        self.static.append(static)

    def path_defined(self, path: str) -> bool:
        """
        Check whether a given path is defined by a previously-added route
        """
        return path in self.paths

    def load_config(self, manager: ServiceManager) -> bool:
        """
        Load the standard route configuration defined by a :class:`ServiceManager` instance
        and its environment variables
        """
        config = manager.load_config_path('ROUTES_CONFIG_PATH', 'routes.yml')
        if not config:
            return False

        limit_forms = manager.env.get('FORMS')
        limit_forms = limit_forms.split() \
            if (limit_forms and limit_forms != 'all') \
            else None

        forms = config.get('forms') or {}
        self.load_form_definitions(forms, limit_forms)

        limit_issuers = manager.env.get('ISSUERS')
        limit_issuers = limit_forms.split() \
            if (limit_issuers and limit_issuers != 'all') \
            else None

        issuers = config.get('issuers') or {}
        self.load_issuer_definitions(issuers, limit_issuers)

        proxy = config.get('proxy') or {}
        self.load_proxy_definitions(proxy)

        static = config.get('static') or {}
        self.load_static_definitions(static)

        return True

    def load_form_definitions(self, config: dict, limit_forms=None) -> None:
        """
        Load a dictionary of form definitions from the application route configuration
        """
        for form_id, form in config.items():
            if limit_forms is not None and form_id not in limit_forms:
                continue
            form_id = form['id'] = form.get('id', form_id)
            if not 'name' in form:
                form['name'] = form_id
            if not form.get('path'):
                form['path'] = '/' + form['name']
            check_form_definition(form)
            self.add_form(form)

    def load_issuer_definitions(self, config: dict, limit_issuers=None) -> None:
        """
        Load a dictionary of issuer definitions from the application route configuration
        """
        for issuer_id, issuer in config.items():
            if limit_issuers is not None and issuer_id not in limit_issuers:
                continue
            issuer_id = issuer['id'] = issuer.get('id', issuer_id)
            if not 'name' in issuer:
                issuer['name'] = issuer_id
            if not issuer.get('path'):
                issuer['path'] = '/' + issuer['name']
            self.add_issuer(issuer)

    def load_static_definitions(self, config: dict) -> None:
        """
        Load a dictionary of static resource definitions from the application route configuration
        """
        for static_id, static in config.items():
            static_id = static['id'] = static.get('id', static_id)
            if not 'target' in static:
                raise ValueError('Missing target path for static resource: {}'.format(static_id))
            if not 'name' in static:
                static['name'] = static_id
            if not static.get('path'):
                static['path'] = '/' + static['name']
            self.add_static(static)

    def load_proxy_definitions(self, config: dict) -> None:
        """
        Load a dictionary of proxy definitions from the application route configuration
        """
        for proxy_id, proxy in config.items():
            proxy_id = proxy['id'] = proxy.get('id', proxy_id)
            if not 'url' in proxy:
                raise ValueError('Missing url for proxy: {}'.format(proxy_id))
            if not 'name' in proxy:
                proxy['name'] = proxy_id
            if not proxy.get('path'):
                proxy['path'] = '/' + proxy['name']
            self.add_proxy(proxy)

    @property
    def routes(self) -> list:
        """
        Accessor for the combined list of routes defined by our configuration
        """
        routes = []

        routes.extend(
            web.view(form['path'], form_handler(form), name=form['name'])
            for form in self.forms)

        routes.extend(
            web.view(issuer['path'] + '/issue-credential', views.issue_credential,
                     name=issuer['name']+'-issue-credential')
            for issuer in self.issuers)
        routes.extend(
            web.view(issuer['path'] + '/construct-proof', views.construct_proof,
                     name=issuer['name']+'-construct-proof')
            for issuer in self.issuers)

        routes.extend(
            web.view(proxy['path']+'/{path:.*}', proxy_handler(proxy), name=proxy['name'])
            for proxy in self.proxies)

        routes.extend(
            web.static(
                static['path'],
                static['target'],
                # follow_symlinks=,
                # append_version=
                show_index=False,
                name=static['name'])
            for static in self.static
        )

        return routes


def check_form_definition(form: dict) -> None:
    """
    Verify a form definition and expand properties as required
    """
    supported_types = ['issue-credential']

    form_id = form.get('id')
    form_type = form.get('type')
    if not form_type:
        raise ValueError('Type not defined for form: {}'.format(form_id))
    if form_type not in supported_types:
        raise ValueError('Unknown form type for {}: {}'.format(form_id, form_type))


def form_handler(form: dict) -> Coroutine:
    """
    Return a request handler for processing form routes
    """
    async def process(request: ClientRequest):
        if request.method == 'GET' or request.method == 'HEAD':
            return await render_form(form, request)
        elif request.method == 'POST':
            return await process_form(form, request)
        return web.Response(status=405)
    return process
