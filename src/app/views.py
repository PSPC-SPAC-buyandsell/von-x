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
#pylint: disable=broad-except

import logging
from sanic import response

from app import APP, get_issuer_endpoint, get_prover_endpoint
from app.services import issuer, prover
from app.viewdefs import config as views_config

LOGGER = logging.getLogger(__name__)

VIEWS = views_config.load_view_definitions(APP)
VIEWS.add_paths('/health', '/status', '/construct-proof', '/submit-claim')
views_config.register_views(APP, VIEWS)


if not VIEWS.path_defined('/'):
    @APP.route('/', methods=['GET', 'HEAD'])
    def index(_request):
        return response.file('app/templates/index.html')

@APP.route('/health', methods=['GET', 'HEAD'])
async def health(_request):
    result = await get_issuer_endpoint(True).request('ready')
    return response.text('ok' if result else '', status=200 if result else 451)

@APP.route('/status', methods=['GET', 'HEAD'])
async def status(_request):
    #result = get_exchange.status()
    result = await get_issuer_endpoint(True).request('status')
    return response.json(result)


# Corresponds with testing code in app/__init__.py
#@APP.route('/hello', methods=['GET', 'HEAD'])
#async def hello(request):
#    hello = get_executor().get_endpoint('hello', True)
#    result = await hello.request('isthereanybodyoutthere')
#    return response.json(result)


@APP.route('/construct-proof', methods=['GET', 'POST'])
async def construct_proof(request):
    proof_name = request.raw_args.get('name')
    if not proof_name:
        return response.text("Missing 'name' parameter", status=400)
    filters = {}
    params = request.json
    if isinstance(params, dict):
        filters = params.get('filters', filters)
        if not isinstance(params, dict):
            return response.text(
                "Parameter 'filters' must be an object",
                status=400)
    try:
        result = await get_prover_endpoint(True).request(
            prover.ConstructProofRequest(proof_name, filters))
        if isinstance(result, prover.ConstructProofResponse):
            ret = {'success': True, 'result': result.value}
        elif isinstance(result, prover.ProverError):
            ret = {'success': False, 'result': result.value}
        else:
            raise ValueError('Unexpected result from prover')
        return response.json(result)
    except Exception as e:
        LOGGER.exception('Error while requesting proof')
        ret = {'success': False, 'result': str(e)}
    return response.json(ret)


@APP.route('/submit-claim', methods=['POST'])
async def submit_claim(request):
    schema_name = request.raw_args.get('schema')
    schema_version = request.raw_args.get('version') or None
    if not schema_name:
        return response.text("Missing 'schema' parameter", status=400)
    if not request.json:
        return response.text(
            'Request body must contain the schema attributes as a JSON object',
            status=400)
    try:
        result = await get_issuer_endpoint(True).request(
            issuer.SubmitClaimRequest(schema_name, schema_version, request.json))
        if isinstance(result, issuer.SubmitClaimResponse):
            ret = {'success': True, 'result': result.value}
        elif isinstance(result, issuer.IssuerError):
            ret = {'success': False, 'result': result.value}
        else:
            raise ValueError('Unexpected result from issuer')
    except Exception as e:
        LOGGER.exception('Error while submitting claim')
        ret = {'success': False, 'result': str(e)}
    return response.json(ret)
