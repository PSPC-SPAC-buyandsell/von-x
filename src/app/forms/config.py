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
from .render import render_form

LOGGER = logging.getLogger(__name__)


class LoadedForms:
    def __init__(self):
        self.forms = []
        self.paths = []
        self.static = []

    def add_form(self, form):
        self.paths.append(form['path'])
        self.forms.append(form)

    def add_static(self, static):
        self.paths.append(static['path'])
        self.static.append(static)

    def path_defined(self, path):
        return path in self.paths


def load_form_definitions(app):
    ret = LoadedForms()
    disallow_paths = ['health', 'status']
    limit_forms = app.config.get('FORMS')
    limit_forms = limit_forms.split() \
        if (limit_forms and limit_forms != 'all') \
        else None

    static = GLOBAL_CONFIG.get('static') or {}
    for static_id, static in static.items():
        if not 'target' in static:
            raise ValueError('Missing target path for static resource: {}'.format(static_id))
        if not 'id' in static:
            static['id'] = static_id
        if not 'name' in static:
            static['name'] = static['id']
        if not 'path' in static:
            static['path'] = '/' + static['name']
        if ret.path_defined(static['path']) or static['path'] in disallow_paths:
            raise ValueError('Duplicate resource path defined: {}'.format(static['path']))
        ret.add_static(static)

    forms = GLOBAL_CONFIG.get('forms') or {}
    forms = expand_tree_variables(forms, app.config)
    for form_id, form in forms.items():
        if limit_forms is not None and form_id not in limit_forms:
            continue

        path = form.get('path')
        if not path:
            raise ValueError('Path not defined for form: {}'.format(form_id))
        if ret.path_defined(path) or path in disallow_paths:
            raise ValueError('Duplicate form path defined: {}'.format(path))
        form_id = form['id'] = form.get('id', form_id)

        expand_form_definition(form)
        ret.add_form(form)

    return ret

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

def auto_register_forms(app):
    loaded = load_form_definitions(app)

    for static in loaded.static:
        app.static(static['path'], static['target'], name=static['id'])

    for form in loaded.forms:
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

    return loaded
