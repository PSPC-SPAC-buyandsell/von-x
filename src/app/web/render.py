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

import json
import logging

from aiohttp import web
from jinja2 import Environment, ChoiceLoader, FileSystemLoader, PackageLoader, nodes
from jinja2.ext import Extension

from app.services import prover, shared

LOGGER = logging.getLogger(__name__)


class StaticExtension(Extension):
    """Jinja2 extension to return a URL for a static resource"""
    tags = set(['static'])

    def parse(self, parser):
        lineno = next(parser.stream).lineno

        args = [parser.parse_expression()]

        return nodes.Output([
            nodes.MarkSafe(nodes.Const('assets/')),
            nodes.MarkSafe(args[0]),
        ], lineno=lineno)


def jinja_env():
    tpl_path = shared.ENV.get('TEMPLATE_PATH')
    loader = PackageLoader('app', 'templates')
    if tpl_path:
        loader = ChoiceLoader([
            loader,
            FileSystemLoader(tpl_path)
        ])
    env = Environment(
        extensions=[StaticExtension],
        loader=loader)
    env.filters['jsonify'] = json.dumps
    return env


JINJA_ENV = jinja_env()


def render_template(name, variables=None):
    if not variables:
        variables = {}
    template = JINJA_ENV.get_template(name)
    return template.render(**variables)


async def render_form(form, request):
    #pylint: disable=broad-except
    proof_req = form.get('proof_request')
    proof_response = None
    if proof_req:
        proof_name = proof_req['name']
        service = request.app['manager'].get_service('prover')
        specs = service.request_specs
        proof_spec = specs.get(proof_name)
        if not proof_spec:
            raise ValueError('Unknown proof request: {}'.format(proof_name))
        filters = {}
        for attr_name in proof_spec['filters']:
            val = request.query.get(attr_name)
            if val is None:
                return web.Response(text='Missing value for filter: {}'.format(attr_name))
            filters[attr_name] = val
        try:
            service = request.app['manager'].get_service_endpoint('prover', True)
            result = await service.request(
                prover.ConstructProofRequest(proof_name, filters))
            if isinstance(result, prover.ConstructProofResponse):
                proof_response = result.value
                proof_response['success'] = True
            elif isinstance(result, prover.ProverError):
                #return response.html('The requested credentials could not be located')
                proof_response = {'success': False}
            else:
                #raise ValueError('Unexpected result from prover')
                LOGGER.error('Unexpected result from prover')
                proof_response = {'success': False}
        except Exception:
            LOGGER.exception('Error while requesting proof')
            return web.Response(text='A communcation error occurred')

    tpl_name = form.get('template', 'index.html')
    tpl_vars = {
        'inputs': {},
        'request': {},
        'proof_response': proof_response,
        'THE_ORG_BOOK_APP_URL': shared.ENV.get('TOB_APP_URL')
    }
    tpl_vars['inputs'].update(request.query)
    tpl_vars['request'].update(request.query)
    if proof_response and proof_response['success']:
        tpl_vars['inputs'].update(proof_response['parsed_proof'])
    tpl_vars.update(form)
    return web.Response(text=render_template(tpl_name, tpl_vars), content_type='text/html')
