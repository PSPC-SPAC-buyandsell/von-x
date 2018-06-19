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

from ..common.manager import ConfigServiceManager
from . import views
from .process import process_form
from .render import render_form

LOGGER = logging.getLogger(__name__)


def get_standard_routes(_app) -> list:
    """
    Get the standard list of routes for the von-x application
    """
    return [
        web.get('/health', views.health),
        web.get('/status', views.status),
        web.get('/ledger-status', views.ledger_status),
        #web.post('/request-proof', views.request_proof),
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

    @classmethod
    def load(cls, manager: ConfigServiceManager) -> 'RouteDefinitions':
        """
        Return a new instance initialized by a :class:`ConfigServiceManager`
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

    def path_defined(self, path: str) -> bool:
        """
        Check whether a given path is defined by a previously-added route
        """
        return path in self.paths

    def load_config(self, manager: ConfigServiceManager) -> bool:
        """
        Load the standard route configuration defined by a :class:`ConfigServiceManager` instance
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

    @property
    def routes(self) -> list:
        """
        Accessor for the combined list of routes defined by our configuration
        """
        routes = []

        routes.extend(
            web.view(form['path'], form_handler(form), name=form['name'])
            for form in self.forms)

        for issuer in self.issuers:
            conn = views.ConnectionView(issuer['id'])
            routes.append(
                web.view(issuer['path'] + '/issue-credential', conn.issue_credential,
                         name=issuer['name']+'-issue-credential'))

        #routes.extend(
        #    web.view(issuer['path'] + '/request-proof', views.request_proof,
        #             name=issuer['name']+'-request-proof')
        #    for issuer in self.issuers)

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
    async def _process(request: ClientRequest):
        if request.method == 'GET' or request.method == 'HEAD':
            return await render_form(form, request)
        elif request.method == 'POST':
            return await process_form(form, request)
        return web.Response(status=405)
    return _process
