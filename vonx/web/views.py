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

from aiohttp import web

from vonx.services import issuer, prover

LOGGER = logging.getLogger(__name__)


def get_manager(request):
    return request.app['manager']

def get_request_target(request, service_name):
    return get_manager(request).get_request_target(service_name)

def service_request(request, service_name, params):
    return get_request_target(request, service_name).request(params)


async def index(_request):
    return web.FileResponse('vonx/templates/index.html')


async def health(request):
    result = await service_request(request, 'issuer', 'ready')
    return web.Response(
        text='ok' if result else '',
        status=200 if result else 451)


async def status(request):
    #result = get_manager(request).exchange.status()
    result = await service_request(request, 'issuer', 'status')
    return web.json_response(result)


async def ledger_status(request):
    mgr = get_manager(request)
    service = mgr.get_service('issuer')
    ledger_url = service.get_ledger_url()
    async with mgr.executor.http as client:
        response = await client.get('{}/status'.format(ledger_url))
    return web.Response(text=await response.text())


async def hello(request):
    service = get_request_target(request, 'hello')
    result = await service.request('isthereanybodyoutthere')
    return web.json_response(result)


async def construct_proof(request):
    proof_name = request.query.get('name')
    if not proof_name:
        return web.Response(text="Missing 'name' parameter", status=400)
    filters = {}
    params = await request.json()
    if isinstance(params, dict):
        filters = params.get('filters', filters)
        if not isinstance(params, dict):
            return web.Response(
                text="Parameter 'filters' must be an object",
                status=400)
    try:
        service = get_request_target(request, 'prover')
        result = await service.request(
            prover.ConstructProofRequest(proof_name, filters))
        if isinstance(result, prover.ConstructProofResponse):
            ret = {'success': True, 'result': result.value}
        elif isinstance(result, prover.ProverError):
            ret = {'success': False, 'result': result.value}
        else:
            raise ValueError('Unexpected result from prover: {}'.format(result))
    except Exception as e:
        LOGGER.exception('Error while requesting proof')
        ret = {'success': False, 'result': str(e)}
    return web.json_response(ret)


async def submit_credential(request):
    schema_name = request.query.get('schema')
    schema_version = request.query.get('version') or None
    if not schema_name:
        return web.Response(text="Missing 'schema' parameter", status=400)
    params = await request.json()
    if not isinstance(params, dict):
        return web.Response(
            text='Request body must contain the schema attributes as a JSON object',
            status=400)
    try:
        service = get_request_target(request, 'issuer')
        result = await service.request(
            issuer.SubmitCredRequest(schema_name, schema_version, params))
        if isinstance(result, issuer.SubmitCredResponse):
            ret = {'success': True, 'result': result.value}
        elif isinstance(result, issuer.IssuerError):
            ret = {'success': False, 'result': result.value}
        else:
            raise ValueError('Unexpected result from issuer')
    except Exception as e:
        LOGGER.exception('Error while submitting credential')
        ret = {'success': False, 'result': str(e)}
    return web.json_response(ret)
