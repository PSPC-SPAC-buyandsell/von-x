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

from aiohttp import web

from . import views
from .process import process_form
from .proxy import proxy_handler
from .render import render_form

LOGGER = logging.getLogger(__name__)


def get_standard_routes(app):
    return [
        web.get('/', views.index),
        web.get('/health', views.health),
        web.get('/status', views.status),
        web.get('/ledger-status', views.ledger_status),
        web.post('/construct-proof', views.construct_proof),
        web.post('/submit-claim', views.submit_claim),
        #web.get('/hello', views.hello),
    ]


def get_custom_routes(app):
    return RouteDefinitions.load(app['manager']).routes


def get_routes(app):
    return get_standard_routes(app) + get_custom_routes(app)


def form_handler(form):
    async def process(request):
        if request.method == 'GET' or request.method == 'HEAD':
            return await render_form(form, request)
        elif request.method == 'POST':
            return await process_form(form, request)
        return web.Response(status=405)
    return process


class RouteDefinitions:
    def __init__(self):
        self.forms = []
        self.paths = []
        self.proxies = []
        self.static = []

    @classmethod
    def load(cls, manager):
        inst = RouteDefinitions()
        inst.load_from_manager(manager)
        return inst

    def add_paths(self, *paths, overwrite=False):
        for path in paths:
            if self.path_defined(path):
                if not overwrite:
                    raise RuntimeError('Duplicate view path defined: {}'.format(path))
            else:
                self.paths.append(path)

    def add_form(self, form):
        self.add_paths(form['path'])
        self.forms.append(form)

    def add_proxy(self, proxy):
        self.add_paths(proxy['path'])
        self.proxies.append(proxy)

    def add_static(self, static):
        self.add_paths(static['path'])
        self.static.append(static)

    def path_defined(self, path):
        return path in self.paths

    def load_from_manager(self, manager):
        limit_forms = manager.env.get('FORMS')
        limit_forms = limit_forms.split() \
            if (limit_forms and limit_forms != 'all') \
            else None
        forms = manager.expand_config('forms')
        self.load_form_definitions(forms, manager, limit_forms)

        proxy = manager.expand_config('proxy')
        self.load_proxy_definitions(proxy)

        static = manager.expand_config('static')
        self.load_static_definitions(static)

    def load_form_definitions(self, config: dict, manager, limit_forms=None):
        for form_id, form in config.items():
            if limit_forms is not None and form_id not in limit_forms:
                continue
            form_id = form['id'] = form.get('id', form_id)
            if not 'name' in form:
                form['name'] = form_id
            if not form.get('path'):
                form['path'] = '/' + form['name']
            self.expand_form_definition(form, manager)
            self.add_form(form)

    def load_static_definitions(self, config: dict):
        for static_id, static in config.items():
            static_id = static['id'] = static.get('id', static_id)
            if not 'target' in static:
                raise ValueError('Missing target path for static resource: {}'.format(static_id))
            if not 'name' in static:
                static['name'] = static_id
            if not static.get('path'):
                static['path'] = '/' + static['name']
            self.add_static(static)

    def load_proxy_definitions(self, config: dict):
        for proxy_id, proxy in config.items():
            proxy_id = proxy['id'] = proxy.get('id', proxy_id)
            if not 'url' in proxy:
                raise ValueError('Missing url for proxy: {}'.format(proxy_id))
            if not 'name' in proxy:
                proxy['name'] = proxy_id
            if not proxy.get('path'):
                proxy['path'] = '/' + proxy['name']
            self.add_proxy(proxy)

    def expand_form_definition(self, form, manager):
        supported_types = ['submit-claim']

        form_id = form.get('id')
        form_type = form.get('type')
        if not form_type:
            raise ValueError('Type not defined for form: {}'.format(form_id))
        if form_type not in supported_types:
            raise ValueError('Unknown form type for {}: {}'.format(form_id, form_type))

        if form_type == 'submit-claim':
            schema = form.get('schema_name')
            version = form.get('schema_version')
            issuer = manager.get_service('issuer')
            if not issuer:
                raise RuntimeError('Issuer manager is not loaded')
            found = issuer.find_issuer_for_schema(schema, version)
            if not found:
                raise ValueError(
                    'Issuer for schema \'{}\' is not defined or not loaded'.format(schema))
            service, claim_type = found
            form['schema'] = claim_type['schema']
            form['issuer_id'] = service.pid

    @property
    def routes(self):
        routes = []

        routes.extend(
            web.view(form['path'], form_handler(form), name=form['name'])
            for form in self.forms)

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
