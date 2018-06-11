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
import aiohttp_jinja2

from vonx.services import prover, manager

LOGGER = logging.getLogger(__name__)


async def render_form(form: dict, request: web.Request) -> web.Response:
    """
    Render a form definition by:

        - performing a proof request if needed,
        - collecting any values needed from the proof request,
        - adding any user input,
        - populating template variables,
        - and rendering the template defined by the form definition

    Args:
        form: The form definition
        request: The request received by aiohttp
    """
    #pylint: disable=broad-except
    proof_req = form.get('proof_request')
    proof_response = None
    service_mgr = request.app['manager']

    if proof_req:
        proof_name = proof_req['name']
        service = service_mgr.get_service_request_target('prover')
        result = await service.request(
            prover.ProofSpecRequest(proof_name))
        proof_spec = None
        if isinstance(result, prover.ProofSpecResponse):
            proof_spec = result.value
        if not proof_spec:
            raise ValueError('Unknown proof request: {}'.format(proof_name))

        params = {}
        if 'params' in proof_req:
            for attr_name, param in proof_req['params'].items():
                if isinstance(param, str):
                    param_from = param
                elif isinstance(param, dict):
                    param_from = param.get('from')
                if param_from:
                    val = request.query.get(param_from)
                    if val is not None and val != '':
                        params[attr_name] = val

        try:
            service = service_mgr.get_service_request_target('prover')
            result = await service.request(
                prover.ConstructProofRequest(proof_name, params))
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
            return web.Response(text='A communication error occurred')

    tpl_name = form.get('template', 'index.html')
    tpl_vars = {
        'inputs': {},
        'request': {},
        'proof_response': proof_response,
        'THE_ORG_BOOK_APP_URL': service_mgr.env.get('TOB_APP_URL')
    }
    tpl_vars['inputs'].update(request.query)
    tpl_vars['request'].update(request.query)
    if proof_response and proof_response['success']:
        # currently flattening attributes from different schemas
        proof_attrs = {}
        for attrs in proof_response['parsed_proof'].values():
            proof_attrs.update(attrs)

        if 'inputs' in proof_req:
            for input_name, claim_name in proof_req['inputs'].items():
                tpl_vars['inputs'][input_name] = proof_attrs.get(claim_name)
        else:
            tpl_vars['inputs'].update(proof_attrs)
    tpl_vars.update(form)
    tpl_vars['path'] = request.rel_url

    return aiohttp_jinja2.render_template(tpl_name, request, tpl_vars)
