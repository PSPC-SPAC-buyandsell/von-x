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

import asyncio
import hashlib
import logging
from random import randint
from typing import Mapping

from von_agent.util import schema_id

from .base import Exchange, ServiceBase, ServiceError, ServiceRequest, ServiceResponse
from .indy import IndyVerifyProofReq, IndyVerifiedProof
from .issuer import ResolveSchemaRequest, ResolveSchemaResponse
from .tob import TobClient, TobClientError
from .util import log_json

LOGGER = logging.getLogger(__name__)


def prepare_request_json(spec: dict):
    """
    Prepare the JSON payload for a proof request

    Args:
        spec: the proof request specification
    """
    request_json = {
        'name': spec['name'],
        'nonce': str(randint(10000000000, 100000000000)),  # FIXME - how best to generate?
        'version': spec['version']
    }
    req_attrs = {}
    for schema in spec['schemas']:
        s_uniq = hashlib.sha1(schema['id'].encode('ascii')).hexdigest()
        for attr in schema['attributes']:
            req_attrs['{}_{}_uuid'.format(s_uniq, attr)] = {
                'name': attr,
                'restrictions': [{
                    'schema_id': schema['id']
                }]
            }
    request_json['requested_attributes'] = req_attrs
    request_json['requested_predicates'] = {}
    return request_json


class ProverError(ServiceError):
    """
    A generic :class:`ServiceError` subclass for Prover exceptions
    """
    pass


class ConstructProofRequest(ServiceRequest):
    """
    A request to construct a proof
    """
    _fields = (
        ('name', str),
        ('filters', dict),
    )


class ConstructProofResponse(ServiceResponse):
    """
    The successful response returned from a proof request
    """
    _fields = (
        'value',
    )


class ProofSpecRequest(ServiceRequest):
    """
    A request to get the definition for a proof request
    """
    _fields = (
        ('name', str),
    )


class ProofSpecResponse(ServiceResponse):
    """
    The successful response returned from a request for a proof definition
    """
    _fields = (
        ('value', dict),
    )


class ProverManager(ServiceBase):
    """
    There should only be one instance of this class in the application.
    It is responsible for packaging proof requests, sending them to TheOrgBook
    and returning the results.
    """

    def __init__(self, pid: str, exchange: Exchange, env: Mapping, request_specs=None):
        super(ProverManager, self).__init__(pid, exchange, env)
        self._ledger_pid = 'indy-ledger'
        self._request_specs = request_specs or {}
        for spec_id, spec in self._request_specs.items():
            if 'name' not in spec:
                spec['name'] = spec_id

    async def _service_sync(self) -> bool:
        return await self._resolve_schemas()

    async def _resolve_schemas(self) -> bool:
        LOGGER.info('Resolving schemas for prover')
        await asyncio.sleep(5)
        synced = False
        while not synced:
            missing = set()
            for spec in self._request_specs.values():
                for schema in spec['schemas']:
                    if 'id' not in schema:
                        s_key = schema['key']
                        if 'did' not in s_key:
                            missing.add((s_key['name'], s_key['version']))
                        else:
                            schema['id'] = schema_id(s_key['did'], s_key['name'], s_key['version'])
            if not missing:
                synced = True
            else:
                for s_key in missing:
                    self.send('issuer-manager', None, ResolveSchemaRequest(*s_key))
                await asyncio.sleep(1)
        return synced

    def _resolved_schema(self, response: ResolveSchemaResponse):
        if not response.issuer_did:
            return
        for spec in self._request_specs.values():
            for schema in spec['schemas']:
                if 'id' not in schema:
                    s_key = schema['key']
                    if 'did' not in s_key and s_key['name'] == response.schema.name \
                            and s_key['version'] == response.schema.version:
                        s_key['did'] = response.issuer_did

    def init_api_client(self, url: str = None) -> TobClient:
        """
        Create a new :class:`TobClient` instance using default initialization parameters

        Args:
            url: a custom value for the URL of the API handling the proof request
        """
        api_url = url or self._env.get('TOB_API_URL')
        return TobClient(self.http, api_url)

    async def construct_proof(self, name: str, filters: Mapping) -> dict:
        """
        Args:
            name: The unique identifier for the proof request definition
            filters: A set of filter values to be applied to the request

        Returns:
            A dict containing `status` and `value` properties representing the response
        """
        spec = self._request_specs.get(name)
        if not spec:
            raise ValueError('Proof request not defined: {}'.format(name))

        api_url = spec.get('url')
        async with self.init_api_client(api_url) as api_client:
            proof_request = prepare_request_json(spec)

            log_json('Requesting proof:', {
                'filters': filters,
                'proof_request': proof_request
            }, LOGGER)

            try:
                proof_response = await api_client.construct_proof(
                    {
                        'filters': filters,
                        'proof_request': proof_request
                    })
                log_json('Got proof response:', proof_response, LOGGER)
            except TobClientError as e:
                if e.status_code == 406:
                    message = await e.response.json()
                    return {'success': False, 'error': message['detail']}
                LOGGER.exception('Error response while requesting proof:')
                return {'success': False, 'error': 'Unexpected response from server'}

        proof = proof_response['proof']

        msg = IndyVerifyProofReq(proof_request, proof)
        reply = await self.submit(self._ledger_pid, msg)
        if not isinstance(reply, IndyVerifiedProof):
            raise RuntimeError('Proof could not be verified, received {}'.format(reply))

        return {
            'success': True,
            'value': {
                'proof': proof,
                'parsed_proof': reply.parsed_proof,
                'verified': reply.verified,
            }
        }

    async def _handle_construct_proof(self, request: ConstructProofRequest):
        """
        Process a :class:`ConstructProofRequest` and send the response to the sending service
        """
        #pylint: disable=broad-except
        try:
            result = await self.construct_proof(request.name, request.filters)
            if result['success']:
                reply = ConstructProofResponse(result['value'])
            else:
                reply = ProverError(result['error'])
        except Exception:
            LOGGER.exception('Exception while constructing proof request:')
            reply = ProverError('Exception while constructing proof request')
        return reply

    async def _service_request(self, request: ServiceRequest) -> ServiceResponse:
        """
        Process a request received from the message bus

        Args:
            request: the request received
        """
        if isinstance(request, ConstructProofRequest):
            spec = self._request_specs.get(request.name)
            if not spec:
                reply = ProverError('Proof request not defined')
            else:
                reply = await self._handle_construct_proof(request)

        elif isinstance(request, ProofSpecRequest):
            spec = self._request_specs.get(request.name)
            if not spec:
                reply = ProverError('Proof request not defined')
            else:
                reply = ProofSpecResponse(spec)

        else:
            reply = None
        return reply

    async def _service_response(self, response: ServiceResponse) -> bool:
        if isinstance(response, ResolveSchemaResponse):
            self._resolved_schema(response)
            return True
        return False
