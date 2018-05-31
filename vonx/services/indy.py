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
import json
import logging
import pathlib
import uuid

import aiohttp
from didauth.indy import seed_to_did
from von_agent.agents import (
    _BaseAgent,
    Issuer as VonIssuer,
    HolderProver as VonHolderProver,
    Verifier as VonVerifier)
from von_agent.error import AbsentSchema, AbsentCredDef
from von_agent.nodepool import NodePool
from von_agent.wallet import Wallet
from von_agent.util import (
    cred_def_id,
    revealed_attrs,
    schema_id,
    schema_key)

from vonx.services.exchange import Exchange, ExchangeError, Message, RequestExecutor
from vonx.services.manager import ServiceManager
from vonx.services.schema import Schema
from vonx.util import log_json

LOGGER = logging.getLogger(__name__)


class IndyLedgerError(ExchangeError):
    """
    A message class for generic errors in processing Indy requests
    """
    pass


class CredOfferRequest:
    """
    The message class representing an request to create a credential offer
    """
    def __init__(self, issuer_id: str, schema: Schema):
        self.issuer_id = issuer_id
        self.schema_def = schema


class CredOfferResponse:
    """
    The message class representing a successful credential offer response
    """
    def __init__(self, issuer_id: str, schema: Schema, payload: dict):
        self.issuer_id = issuer_id
        self.schema_def = schema
        self.payload = payload


class CredCreateRequest:
    """
    The message class representing an request to create a credential
    """
    def __init__(self, cred_offer: CredOfferResponse, cred_req: dict, cred_data: dict):
        self.cred_offer = cred_offer
        self.cred_req = cred_req
        self.cred_data = cred_data


class CredCreateResponse:
    """
    The message class representing a successful credential creation
    """
    def __init__(self, issuer_id: str, payload: dict):
        self.issuer_id = issuer_id
        self.payload = payload


class ResolveDidRequest:
    """
    The message class representing a request to resolve a DID
    """
    def __init__(self, seed: str):
        self.seed = seed


class ResolveDidResponse:
    """
    The message class representing a response to DID resolution request
    """
    def __init__(self, seed: str, did: str):
        self.seed = seed
        self.did = did


class RegisterIssuerRequest:
    """
    The message class representing a request to register an issuer
    """
    def __init__(self, issuer_cfg: dict):
        self.config = issuer_cfg


class RegisterIssuerResponse:
    """
    The message class representing a request to resolve a DID
    """
    def __init__(self, issuer_id: str):
        self.issuer_id = issuer_id


class IndyIssuerStatus:
    """
    The message class representing an issuer status update
    """
    def __init__(self, issuer_id: str, status: dict):
        self.issuer_id = issuer_id
        self.status = status


class VerifyProofRequest:
    """
    The message class representing a request to verify a proof
    """
    def __init__(self, proof_req, proof):
        self.proof_req = proof_req
        self.proof = proof


class VerifyProofResponse:
    """
    The message class representing a successful proof verification
    """
    def __init__(self, verified, parsed_proof):
        self.verified = verified
        self.parsed_proof = parsed_proof


class WalletConfig:
    def __init__(self, **params):
        self.name = params.get('name')
        if not self.name:
            raise ValueError('Missing wallet name')
        self.seed = params.get('seed')
        if not self.seed:
            raise ValueError("Missing seed for wallet '{}'".format(self.name))
        if len(self.seed) != 32:
            raise ValueError('Wallet seed length is not 32 characters: {}'.format(self.seed))
        self.genesis_path = params.get('genesis_path')
        self.type = params.get('type', None) # or virtual?
        self.params = params.get('params', {})
        if 'freshness_time' not in self.params:
            self.params['freshness_time'] = 0
        self.creds = {'key': ''}


class AgentWrapper:
    """
    A wrapper for the :class:`_BaseAgent` instance which handles configuration loading
    and allows the wallet to be kept open between requests
    """
    def __init__(self, wallet_config: WalletConfig, instance_cls, issuer_type: str, ext_cfg=None):
        if not wallet_config.genesis_path:
            raise ValueError('Missing genesis_path for wallet configuration')

        self._pool = NodePool(
            wallet_config.name + '-' + issuer_type,
            wallet_config.genesis_path)

        self._instance_cls = instance_cls
        self._instance = None
        self._wallet = Wallet(
            self._pool,
            wallet_config.seed,
            wallet_config.name + '-' + issuer_type + '-Wallet',
            wallet_config.type,
            wallet_config.params,
            wallet_config.creds)
        self._ext_cfg = ext_cfg
        self._opened = None
        self._keep_open = False

    @property
    def opened(self):
        return self._opened

    @property
    def instance(self):
        return self._instance

    def keep_open(self, flag=True):
        """
        Set the keep-open flag to keep the wallet open between requests
        """
        self._keep_open = flag

    async def open(self, keep_open=True) -> _BaseAgent:
        """
        Open the connection to the transaction pool and wallet
        """
        if keep_open:
            self._keep_open = True
        if self._opened:
            return self._opened
        await self._pool.open()
        self._instance = self._instance_cls(await self._wallet.create(), self._ext_cfg)
        self._opened = await self._instance.open()
        if isinstance(self._instance, VonHolderProver):
            # NOTE: should only create this once, and only in the root wallet (virtual_wallet == None)
            await self._instance.create_link_secret(str(uuid.uuid4()))
        return self._opened

    async def close(self):
        """
        Close the wallet and transaction pool connections
        """
        if self._opened:
            await self._instance.close()
            await self._pool.close()
        self._opened = None
        self._keep_open = False

    async def __aenter__(self):
        return await self.open(False)

    async def __aexit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            LOGGER.exception('Exception in VON %s:', self._wallet.name)
        if not self._keep_open:
            await self.close()


class IndyIssuerConfig:
    def __init__(self, **params):
        self.agent = None
        self.auto_register = params.get('auto_register', True)
        self.did = params.get('did')
        self.endpoint = params.get('endpoint')
        self.ident = params.get('id')
        self.manager_pid = params.get('manager_pid')
        self.registered = False
        self.schemas = []
        self.synced = False
        self.wrapper = None
        wallet_cfg = params.get('wallet') or {}
        if 'name' not in wallet_cfg:
            wallet_cfg['name'] = self.ident
        self.wallet_config = WalletConfig(**wallet_cfg)

        schemas = params.get('schemas')
        if schemas:
            for schema in schemas:
                self.add_schema(schema)

    @property
    def extended_config(self):
        ret = {}
        if self.endpoint:
            ret['endpoint'] = self.endpoint

    def add_schema(self, schema):
        self.schemas.append({
            'definition': schema.copy(),
            'ledger': None,
            'cred_def': None,
        })

    def find_schema(self, match: Schema) -> dict:
        for schema in self.schemas:
            defn = schema['definition']
            if defn.compare(match):
                return schema
        return None


class IndyLedger(RequestExecutor):
    """
    A class for managing interactions with the Hyperledger Indy ledger
    """
    def __init__(self, pid: str, exchange: Exchange, spec: dict = None):
        self._config = {}
        self._genesis_path = None
        self._issuers = {}
        self._ledger_url = None
        self._status = {}
        self._sync_lock = None
        self._verifier = None

        self._update_config(spec)
        super(IndyLedger, self).__init__(pid, exchange)
        self._init_status()

    @classmethod
    def create(cls, service_mgr: ServiceManager, pid: str = 'indy-ledger'):
        """
        Initialize the Hyperledger Indy service

        Args:
            service_mgr: the shared :class:`ServiceManager` instance
            pid: the identifier for the :class:`IndyLedger` service

        Returns:
            the initialized :class:`IndyLedger` instance
        """
        env = service_mgr.env
        genesis_path = env.get('INDY_GENESIS_PATH')
        if not genesis_path:
            raise ValueError('Indy genesis transaction path (INDY_GENESIS_PATH) not defined')
        ledger_url = env.get('INDY_LEDGER_URL')
        if not ledger_url:
            raise ValueError('INDY_LEDGER_URL not defined')

        spec = {
            'auto_register': env.get('AUTO_REGISTER_DID', 1),
            'genesis_path': genesis_path,
            'ledger_url': ledger_url,
        }
        LOGGER.info('Initializing Indy ledger service')
        return cls(pid, service_mgr.exchange, spec)

    def _update_config(self, spec) -> None:
        """
        Load configuration settings
        """
        if spec:
            self._config.update(spec)
        if 'ledger_url' in spec:
            self._ledger_url = spec['ledger_url']

    def _init_status(self) -> None:
        self._update_status({
            'id': self._pid,
            'ready': False,
            'syncing': False,
            'started': False,
        })

    def _update_status(self, update=None, _silent=False) -> None:
        if update:
            self._status.update(update)

    def start(self):
        """
        Start listening for messages and initialize the ledger connection
        """
        self._sync_lock = asyncio.Lock()
        ret = super(IndyLedger, self).start()
        self.run_task(self._sync())
        return ret

    async def _sync(self) -> bool:
        """
        Perform the initial setup of the ledger connection
        """
        async with self._sync_lock:
            await asyncio.sleep(1) # avoid odd TimeoutError on genesis txn retrieval
            self._update_status({'syncing': True})
            await self._check_genesis_path()
            for issuer in self._issuers.values():
                await self._sync_issuer(issuer)
            self._update_status({'syncing': False})

    def _add_issuer(self, **params) -> str:
        """
        Add an issuer configuration
        """
        if 'id' not in params:
            raise ValueError("Missing 'id' for issuer")
        cfg = IndyIssuerConfig(**params)
        self._issuers[cfg.ident] = cfg
        return cfg.ident

    async def _sync_issuer(self, issuer: IndyIssuerConfig):
        if not issuer.synced:
            if not issuer.wrapper:
                LOGGER.info('Init Indy issuer %s with seed %s', issuer.ident, issuer.wallet_config.seed)

                issuer.wallet_config.genesis_path = self._genesis_path
                issuer.wrapper = AgentWrapper(
                    issuer.wallet_config,
                    VonIssuer,
                    'Issuer',
                    issuer.extended_config)

            # FIXME - catch sync exceptions here
            if not issuer.agent:
                issuer.agent = await issuer.wrapper.open()
                issuer.did = issuer.agent.did

            if not issuer.registered:
                # check DID is registered
                auto_register = self._config.get('auto_register', True) and issuer.auto_register
                await self._check_registration(issuer.agent, auto_register)

                # check endpoint is registered (if any)
                #await self._check_endpoint(issuer.agent, issuer.endpoint)

            # publish schemas
            for schema in issuer.schemas:
                await self._publish_schema(issuer.agent, schema)

            issuer.synced = True
            if issuer.manager_pid:
                self.send_noreply(
                    issuer.manager_pid,
                    IndyIssuerStatus(issuer.ident, {'did': issuer.did, 'synced': True}))

            LOGGER.info('Indy issuer synced: %s', issuer.ident)

    async def _check_genesis_path(self) -> None:
        """
        Make sure that the genesis path is defined, and download the transaction file if needed.

        Returns:
            the resolved genesis transaction path
        """
        if not self._genesis_path:
            path = self._config.get('genesis_path')
            if not path:
                raise ValueError('Missing genesis_path')
            genesis_path = pathlib.Path(path)
            if not genesis_path.exists():
                ledger_url = self._ledger_url
                if not ledger_url:
                    raise ValueError('Cannot retrieve genesis transaction without ledger_url')
                parent_path = pathlib.Path(genesis_path.parent)
                if not parent_path.exists():
                    parent_path.mkdir(parents=True)
                await self._fetch_genesis_txn(ledger_url, genesis_path)
            elif genesis_path.is_dir():
                raise ValueError('genesis_path must not point to a directory')
            self._genesis_path = path

    async def _fetch_genesis_txn(self, ledger_url: str, target_path: str) -> bool:
        """
        Download the genesis transaction file from the ledger server
        """
        LOGGER.info('Fetching genesis transaction file from %s/genesis', ledger_url)
        async with aiohttp.ClientSession(read_timeout=30) as client:
            response = await client.get('{}/genesis'.format(ledger_url))
        if response.status != 200:
            raise RuntimeError('Error downloading genesis file: status {}'.format(
                response.status))
        data = await response.text()

        # check data is valid json
        LOGGER.debug('Genesis transaction response: %s', data)
        lines = data.splitlines()
        if not lines or not json.loads(lines[0]):
            raise RuntimeError('Genesis transaction file is not valid JSON')

        # write result to provided path
        with target_path.open('x') as output_file:
            output_file.write(data)
        return True

    async def _check_registration(self, agent: _BaseAgent, auto_register=True):
        """
        Look up our nym on the ledger and register it if not present
        """
        did = agent.did
        LOGGER.debug('Checking DID registration %s', did)
        nym_json = await agent.get_nym(did)
        LOGGER.debug('get_nym result for %s: %s', did, nym_json)

        nym_info = json.loads(nym_json)
        if not nym_info:
            if not auto_register:
                raise RuntimeError(
                    'DID is not registered on the ledger and auto-registration disabled')

            ledger_url = self._ledger_url
            if not ledger_url:
                raise ValueError('Cannot register DID without ledger_url')
            LOGGER.info('Registering DID %s', did)

            async with aiohttp.ClientSession(read_timeout=30) as client:
                response = await client.post(
                    '{}/register'.format(ledger_url),
                    json={'did': did, 'verkey': agent.verkey})
                if response.status != 200:
                    raise RuntimeError(
                        'DID registration failed: {}'.format(await response.text()))
                nym_info = await response.json()
                LOGGER.debug('Registration response: %s', nym_info)
                if not nym_info or not nym_info['did']:
                    raise RuntimeError(
                        'DID registration failed: {}'.format(nym_info))

    async def _check_endpoint(self, agent: _BaseAgent, endpoint: str):
        """
        Look up our endpoint on the ledger and register it if not present
        """
        if not endpoint:
            return None
        did = agent.did
        LOGGER.debug('Checking endpoint registration %s', endpoint)
        endp_json = await agent.get_endpoint(did)
        LOGGER.debug('get_endpoint result for %s: %s', did, endp_json)

        endp_info = json.loads(endp_json)
        if not endp_info:
            endp_info = await agent.send_endpoint()
            LOGGER.debug('Endpoint stored: %s', endp_info)
        return endp_info

    async def _publish_schema(self, issuer: VonIssuer, schema: dict) -> None:
        """
        Check the ledger for a specific schema and version, and publish it if not found

        Args:
            schema: a dict which will be updated with the published schema and credential def
        """

        if not schema or 'definition' not in schema:
            raise ValueError('Missing schema definition')
        definition = schema['definition']

        if not schema.get('ledger'):
            LOGGER.info('Checking for schema: %s (%s)', definition.name, definition.version)
            # Check if schema exists on ledger

            try:
                s_key = schema_key(schema_id(issuer.did, definition.name, definition.version))
                schema_json = await issuer.get_schema(s_key)
                ledger_schema = json.loads(schema_json)
                log_json('Schema found on ledger:', ledger_schema, LOGGER)
            except AbsentSchema:
                # If not found, send the schema to the ledger
                LOGGER.info('Publishing schema: %s (%s)', definition.name, definition.version)
                schema_json = await issuer.send_schema(json.dumps({
                    'name': definition.name,
                    'version': definition.version,
                    'attr_names': definition.attr_names}))
                ledger_schema = json.loads(schema_json)
                if not ledger_schema or not ledger_schema.get('seqNo'):
                    raise RuntimeError('Schema was not published to ledger')
                log_json('Published schema:', ledger_schema, LOGGER)
            schema['ledger'] = ledger_schema

        if not schema.get('cred_def'):
            # Check if credential definition has been published
            LOGGER.info('Checking for credential def: %s (%s)', definition.name, definition.version)

            try:
                cred_def_json = await issuer.get_cred_def(cred_def_id(issuer.did, schema['ledger']['seqNo']))
                cred_def = json.loads(cred_def_json)
                log_json('Credential def found on ledger:', cred_def, LOGGER)
            except AbsentCredDef:
                # If credential definition is not found then publish it
                LOGGER.info('Publishing credential def: %s (%s)', definition.name, definition.version)
                cred_def_json = await issuer.send_cred_def(schema_json, revocation=False)
                cred_def = json.loads(cred_def_json)
                log_json('Published credential def:', cred_def, LOGGER)
            schema['cred_def'] = cred_def

    async def _handle_create_cred_offer(self, request: CredOfferRequest, reply_to: str, ref) -> bool:
        """
        Create a credential offer for TheOrgBook

        Args:
            request: the message wrapping the request for a credential offer
            reply_to: the service requesting this cred offer
            ref: the identifier for the originating message
        """
        issuer = self._issuers[request.issuer_id]
        schema = issuer.find_schema(request.schema_def)

        LOGGER.info(
            'Creating indy credential offer for issuer %s, schema %s',
            issuer.ident, schema['definition'].name)
        cred_offer_json = await issuer.agent.create_cred_offer(schema['ledger']['seqNo'])

        # format currently expected by TheOrgBook
        msg = CredOfferResponse(request.issuer_id, request.schema_def, {
            'credential-offer': json.loads(cred_offer_json),
            'credential-definition': schema['cred_def'],
        })
        return self.send_noreply(reply_to, msg, ref)

    async def _handle_create_cred(self, request: CredCreateRequest, reply_to: str, ref) -> bool:
        """
        Create a credential for TheOrgBook

        Args:
            request: the message wrapping the request to store a credential
            reply_to: the service requesting this credential
            ref: the identifier for the originating message
        """
        issuer = self._issuers[request.cred_offer.issuer_id]
        schema = issuer.find_schema(request.cred_offer.schema_def)
        cred_request = request.cred_req['credential_request']
        cred_request_metadata = request.cred_req['credential_request_metadata_json']

        (cred_json, _cred_revoc_id) = await issuer.agent.create_cred(
            request.cred_offer.payload['claim_offer'],
            cred_request,
            request.cred_data)

        msg = CredCreateResponse(request.cred_offer.issuer_id, {
            'claim_type': schema['definition'].name,
            'claim_data': json.loads(cred_json),
            'issuer_did': issuer.agent.did,
            'cred_def': schema['cred_def'],
            'cred_req_metadata': cred_request_metadata,
        })
        return self.send_noreply(reply_to, msg, ref)

    async def get_verifier(self):
        if not self._verifier:
            wallet_cfg = WalletConfig(
                name='GenericVerifier',
                seed='verifier-seed-000000000000000000',
                genesis_path=self._genesis_path)
            self._verifier = AgentWrapper(wallet_cfg, VonVerifier, 'Verifier')
            await self._verifier.open()
        return self._verifier.instance

    async def _handle_verify_proof(self, request: VerifyProofRequest, reply_to: str, ref) -> bool:
        """
        Verify a proof returned by TheOrgBook

        Args:
            request: the message wrapping the request to verify a proof
            reply_to: the service requesting this verification
            ref: the identifier for the originating message
        """
        verifier = await self.get_verifier()
        result = await verifier.verify_proof(
            request.proof_req,
            request.proof)
        parsed_proof = revealed_attrs(request.proof)

        msg = VerifyProofResponse(result, parsed_proof)
        return self.send_noreply(reply_to, msg, ref)

    def process(self, message: Message) -> None:
        """
        Process a message from the exchange and send the reply, if any

        Args:
            message: the message to be processed
        """
        from_pid, request, ident = message.from_pid, message.body, message.ident

        if self._handle_response(message):
            return

        elif request == 'sync':
            self.run_task(self._sync())
            self.send_noreply(from_pid, True, ident)

        elif isinstance(request, RegisterIssuerRequest):
            try:
                issuer_id = self._add_issuer(**request.config)
                msg = RegisterIssuerResponse(issuer_id)
                self.run_task(self._sync())
            except ValueError as e:
                msg = IndyLedgerError(str(e))
            self.send_noreply(from_pid, msg, ident)

        elif isinstance(request, CredOfferRequest):
            self.run_task(self._handle_create_cred_offer(request, from_pid, ident))

        elif isinstance(request, CredCreateRequest):
            self.run_task(self._handle_create_cred(request, from_pid, ident))

        elif isinstance(request, VerifyProofRequest):
            self.run_task(self._handle_verify_proof(request, from_pid, ident))

        elif isinstance(request, ResolveDidRequest):
            msg = ResolveDidResponse(request.seed, seed_to_did(request.seed))
            self.send_noreply(from_pid, msg, ident)

        elif request == 'ready':
            self.send_noreply(from_pid, self._status.get('ready'), ident)

        elif request == 'status':
            self.send_noreply(from_pid, self._status.copy(), ident)

        else:
            raise ValueError('Unexpected message from {}: {}'.format(from_pid, request))
