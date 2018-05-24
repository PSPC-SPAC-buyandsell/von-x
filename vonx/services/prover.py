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
from random import randint
from typing import Mapping

from vonx.services.exchange import Exchange, ExchangeError, Message, RequestExecutor
from vonx.services.manager import ServiceManager
from vonx.services.tob import TobClient, TobClientError
from vonx.services.von import VonClient
from vonx.util import log_json

LOGGER = logging.getLogger(__name__)


def init_prover_manager(service_manager: ServiceManager, pid:str='prover-manager'):
    """
    Create an instance of the :class:`ProverManager`, loading the defined configuration
    from the :class:`ServiceManager` instance
    """
    config_requests = service_manager.services_config('proof_requests')
    LOGGER.info('Initializing proof request manager')
    return ProverManager(pid, service_manager.exchange, service_manager.env, config_requests)


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


class ProverManager(RequestExecutor):
    """
    There should only be one instance of this class in the application.
    It is responsible for packaging proof requests, sending them to TheOrgBook
    and returning the results.
    """

    def __init__(self, pid: str, exchange: Exchange, env: Mapping=None, request_specs=None):
        super(ProverManager, self).__init__(pid, exchange)
        self._env = env or {}
        self._api_did = None
        self._request_specs = request_specs or {}
        for spec_id, spec in self._request_specs.items():
            if 'name' not in spec:
                spec['name'] = spec_id
        self._ready = True

    def ready(self) -> bool:
        """
        Check the ready status of the service
        """
        return self._ready

    def status(self) -> dict:
        """
        Check the extended status of the service
        """
        return {
            'api_did': self._api_did,
            'ready': self._ready
        }

    @property
    def request_specs(self) -> list:
        """
        An accessor for the list of defined proof requests specifications
        """
        return self._request_specs

    def init_von_client(self) -> VonClient:
        """
        Create a new :class:`VonClient` instance using default initialization parameters
        """
        cfg = {
            'genesis_path': self._env.get('INDY_GENESIS_PATH'),
            'ledger_url': self._env.get('INDY_LEDGER_URL'),
            'wallet': {
                'name': 'Generic', # FIXME
                'seed': 'verifier-seed-000000000000000000' # FIXME - what seed to use here?
            }
        }
        return VonClient(cfg)

    def init_tob_client(self, url:str=None) -> TobClient:
        """
        Create a new :class:`TobClient` instance using default initialization parameters

        Args:
            url: a custom value for the URL of the API handling the proof request
        """
        cfg = {
            'api_url': url or self._env.get('TOB_API_URL')
        }
        return TobClient(cfg)

    def _prepare_request_json(self, spec):
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
            for attr in schema['attributes']:
                # FIXME - support attribute renaming
                req_attrs[attr] = {
                    'name': attr,
                    'restrictions': [{
                        # schema_key can include name, version, and did
                        'schema_key': schema['key'].copy()
                    }]
                }
        request_json['requested_attrs'] = req_attrs
        request_json['requested_predicates'] = {}
        return request_json

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
        proof_request = self._prepare_request_json(spec)
        tob_uri = spec.get('url')

        tob_client = self.init_tob_client(tob_uri)
        von_client = self.init_von_client()

        log_json('Requesting proof:', {
            'filters': filters,
            'proof_request': proof_request
        }, LOGGER)

        try:
            proof_response = await tob_client.post_json(
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
        parsed_proof = {}
        for attr in proof['requested_proof']['revealed_attrs']:
            parsed_proof[attr] = \
                proof['requested_proof']['revealed_attrs'][attr][1]

        async with await von_client.create_verifier() as von_verifier:
            verified = await von_verifier.verify_proof(
                proof_request,
                proof
            )

        return {
            'success': True,
            'value': {
                'proof': proof,
                'parsed_proof': parsed_proof,
                'verified': verified
            }
        }

    async def _process_construct_proof(self, from_pid: str, ident, request: ConstructProofRequest) -> bool:
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

    def process(self, message: Message):
        """
        Process a request received from the message bus

        Args:
            message: the message received
        """
        from_pid, request, ident, ref = message.from_pid, message.request, message.ident, message.ref
        if isinstance(request, ConstructProofRequest):
            spec = self._request_specs.get(request.name)
            if not spec:
                self.send_noreply(from_pid, ProverError('Proof request not defined'), ident)
            else:
                self.run_task(self._process_construct_proof(from_pid, ident, request))
        elif request == 'ready':
            self.send_noreply(from_pid, self.ready(), ident)
        elif request == 'status':
            self.send_noreply(from_pid, self.status(), ident)
        else:
            raise ValueError('Unexpected message from {}: {}'.format(from_pid, request))
