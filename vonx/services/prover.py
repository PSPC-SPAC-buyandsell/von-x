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

from vonx.services.exchange import Exchange, ExchangeError, Message, RequestExecutor
from vonx.services.indy import VerifyProofRequest, VerifyProofResponse
from vonx.services.issuer import ResolveSchemaRequest, ResolveSchemaResponse
from vonx.services.manager import ServiceManager
from vonx.services.tob import TobClient, TobClientError
from vonx.util import log_json

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


class ProverError(ExchangeError):
    """
    A generic :class:`ExchangeError` subclass for Prover exceptions
    """
    pass


class ConstructProofRequest:
    """
    A request to construct a proof
    """
    def __init__(self, name, filters):
        self.name = name
        self.filters = filters


class ConstructProofResponse:
    """
    The successful response returned from a proof request
    """
    def __init__(self, value):
        self.value = value


class ProofSpecRequest:
    """
    A request to get the definition for a proof request
    """
    def __init__(self, name):
        self.name = name


class ProofSpecResponse:
    """
    The successful response returned from a request for a proof definition
    """
    def __init__(self, value):
        self.value = value


class ProverManager(RequestExecutor):
    """
    There should only be one instance of this class in the application.
    It is responsible for packaging proof requests, sending them to TheOrgBook
    and returning the results.
    """

    def __init__(self, pid: str, exchange: Exchange, env: Mapping = None, request_specs=None):
        super(ProverManager, self).__init__(pid, exchange)
        self._env = env or {}
        self._ledger_pid = 'indy-ledger'
        self._request_specs = request_specs or {}
        self._status = {
            'ready': False,
        }
        for spec_id, spec in self._request_specs.items():
            if 'name' not in spec:
                spec['name'] = spec_id

    @classmethod
    def create(cls, service_mgr: ServiceManager, pid: str = 'prover-manager'):
        """
        Create an instance of the :class:`ProverManager`, loading the defined configuration
        from the :class:`ServiceManager` instance
        """
        config_requests = service_mgr.services_config('proof_requests')
        LOGGER.info('Initializing proof request manager')
        return cls(pid, service_mgr.exchange, service_mgr.env, config_requests)

    def start(self):
        ret = super(ProverManager, self).start()
        self.run_task(self._resolve_schemas())
        return ret

    async def _resolve_schemas(self):
        LOGGER.info('Resolving schemas for prover')
        await asyncio.sleep(5)
        while not self._status['ready']:
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
                self._status['ready'] = True
            else:
                for s_key in missing:
                    self.send('issuer-manager', None, ResolveSchemaRequest(*s_key))
                await asyncio.sleep(1)
        LOGGER.info('Completed prover initialization')

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
        return TobClient(api_url)

    async def construct_proof(self, http_client, name: str, filters: Mapping) -> dict:
        """
        Args:
            http_client: The :class:`ClientSession` to use for the request, which is also
                responsible for adding authentication headers
            name: The unique identifier for the proof request definition
            filters: A set of filter values to be applied to the request

        Returns:
            A dict containing `status` and `value` properties representing the response
        """
        spec = self._request_specs.get(name)
        if not spec:
            raise ValueError('Proof request not defined: {}'.format(name))

        api_url = spec.get('url')
        api_client = self.init_api_client(api_url)
        proof_request = prepare_request_json(spec)

        log_json('Requesting proof:', {
            'filters': filters,
            'proof_request': proof_request
        }, LOGGER)

        try:
            proof_response = await api_client.post_json(
                http_client,
                'bcovrin/construct-proof',
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

        msg = VerifyProofRequest(proof_request, proof)
        reply = await self.submit(self._ledger_pid, msg)
        if not isinstance(reply, VerifyProofResponse):
            raise RuntimeError('Proof could not be verified, received {}'.format(reply))

        return {
            'success': True,
            'value': {
                'proof': proof,
                'parsed_proof': reply.parsed_proof,
                'verified': reply.verified,
            }
        }

    async def _process_construct_proof(self, from_pid: str, ident,
                                       request: ConstructProofRequest) -> bool:
        """
        Process a :class:`ConstructProofRequest` and send the response to the sending service
        """
        #pylint: disable=broad-except
        try:
            async with self.http as http_client:
                result = await self.construct_proof(http_client, request.name, request.filters)
            if result['success']:
                reply = ConstructProofResponse(result['value'])
            else:
                reply = ProverError(result['error'])
            self.send_noreply(from_pid, reply, ident)
        except Exception:
            LOGGER.exception('Exception while constructing proof request:')
            msg = ProverError('Exception while constructing proof request')
            self.send_noreply(from_pid, msg, ident)

    def process(self, message: Message) -> bool:
        """
        Process a request received from the message bus

        Args:
            message: the message received
        """
        from_pid, request, ident = message.from_pid, message.body, message.ident

        if self._handle_response(message):
            return

        elif isinstance(request, ConstructProofRequest):
            spec = self._request_specs.get(request.name)
            if not spec:
                self.send_noreply(from_pid, ProverError('Proof request not defined'), ident)
            else:
                self.run_task(self._process_construct_proof(from_pid, ident, request))

        elif isinstance(request, ResolveSchemaResponse):
            self._resolved_schema(request)

        elif isinstance(request, ProofSpecRequest):
            spec = self._request_specs.get(request.name)
            if not spec:
                self.send_noreply(from_pid, ProverError('Proof request not defined'), ident)
            else:
                self.send_noreply(from_pid, ProofSpecResponse(spec), ident)

        elif request == 'ready':
            self.send_noreply(from_pid, self._status['ready'], ident)

        elif request == 'status':
            self.send_noreply(from_pid, self._status.copy(), ident)

        else:
            raise ValueError('Unexpected message from {}: {}'.format(from_pid, request))
