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

from app import GLOBAL_CONFIG, get_issuer_manager
from app.settings import expand_tree_variables
from .process import process_form
from .proxy import get_proxy_handler, ProxyConnHandler
from .render import render_form

LOGGER = logging.getLogger(__name__)


class ViewDefinitions:
    def __init__(self):
        self.forms = []
        self.paths = []
        self.proxies = []
        self.static = []

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


def load_view_definitions(app):
    view_defs = ViewDefinitions()

    limit_forms = app.config.get('FORMS')
    limit_forms = limit_forms.split() \
        if (limit_forms and limit_forms != 'all') \
        else None
    forms = GLOBAL_CONFIG.get('forms') or {}
    forms = expand_tree_variables(forms, app.config)
    load_form_definitions(forms, view_defs, limit_forms)

    proxy = GLOBAL_CONFIG.get('proxy') or {}
    proxy = expand_tree_variables(proxy, app.config)
    load_proxy_definitions(proxy, view_defs)

    static = GLOBAL_CONFIG.get('static') or {}
    static = expand_tree_variables(static, app.config)
    load_static_definitions(static, view_defs)

    return view_defs


def load_form_definitions(config: dict, view_defs: ViewDefinitions, limit_forms=None):
    for form_id, form in config.items():
        if limit_forms is not None and form_id not in limit_forms:
            continue
        form_id = form['id'] = form.get('id', form_id)
        if not 'name' in form:
            form['name'] = form_id
        if not form.get('path'):
            form['path'] = '/' + form['name']
        expand_form_definition(form)
        view_defs.add_form(form)


def load_static_definitions(config: dict, view_defs: ViewDefinitions):
    for static_id, static in config.items():
        static_id = static['id'] = static.get('id', static_id)
        if not 'target' in static:
            raise ValueError('Missing target path for static resource: {}'.format(static_id))
        if not 'name' in static:
            static['name'] = static_id
        if not static.get('path'):
            static['path'] = '/' + static['name']
        view_defs.add_static(static)


def load_proxy_definitions(config: dict, view_defs: ViewDefinitions):
    for proxy_id, proxy in config.items():
        proxy_id = proxy['id'] = proxy.get('id', proxy_id)
        if not 'url' in proxy:
            raise ValueError('Missing url for proxy: {}'.format(proxy_id))
        if not 'name' in proxy:
            proxy['name'] = proxy_id
        if not proxy.get('path'):
            proxy['path'] = '/' + proxy['name']
        view_defs.add_proxy(proxy)


def expand_form_definition(form):
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
        mgr = get_issuer_manager()
        if not mgr:
            raise RuntimeError('Issuer manager is not loaded')
        found = mgr.find_issuer_for_schema(schema, version)
        if not found:
            raise ValueError(
                'Issuer for schema \'{}\' is not defined or not loaded'.format(schema))
        service, claim_type = found
        form['schema'] = claim_type['schema']
        form['issuer_id'] = service.get_pid()


def do_render_form(form):
    async def do_render(request):
        return await render_form(form, request)
    return do_render

def do_process_form(form):
    async def do_process(request):
        return await process_form(form, request)
    return do_process


def register_views(app, view_defs: ViewDefinitions):
    for form in view_defs.forms:
        app.add_route(
            do_render_form(form),
            form['path'],
            methods=['GET', 'HEAD'],
            name=form['id']+'_render')
        app.add_route(
            do_process_form(form),
            form['path'],
            methods=['POST'],
            name=form['id']+'_process')

    # shared connection pool for proxies
    conn_handler = ProxyConnHandler()
    for proxy in view_defs.proxies:
        app.add_route(get_proxy_handler(proxy, conn_handler), proxy['path']+'/<path:path>')

    for static in view_defs.static:
        app.static(static['path'], static['target'], name=static['id'])

    return view_defs
