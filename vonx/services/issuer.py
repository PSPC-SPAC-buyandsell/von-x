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
import logging
from typing import Mapping

import aiohttp
from didauth.ext.aiohttp import SignedRequest, SignedRequestAuth

from vonx.services.exchange import Exchange, ExchangeError, Message, RequestExecutor
from vonx.services import indy
from vonx.services.manager import ServiceManager
from vonx.services.schema import Schema, SchemaManager
from vonx.services.tob import TobClient, TobClientError
from vonx.util import log_json

LOGGER = logging.getLogger(__name__)


def load_cred_request(cred_type: Mapping, request: Mapping, validate=True) -> dict:
    """
    Convert a dictionary of input parameters into a set of only defined credential
    attributes, and optionally validate the credential format

    Args:
        cred_type: the credential type definition
        request: the claim attribute values
        validate: Whether to validate the credential against its schema value restrictions

    Returns:
        The loaded credential attributes
    """
    cred = {}
    for attr in cred_type['schema'].attr_names:
        cred[attr] = request.get(attr)
    if validate:
        cred_type['schema'].validate(cred)
    return cred


def load_cred_definitions(values: list, schema_mgr: SchemaManager) -> list:
    """
    Load the credential types defined by our config into a standard format
    """
    cred_types = []
    for ctype in (values or []):
        if 'schema' not in ctype:
            raise ValueError("Credential type must define 'schema'")
        if isinstance(ctype['schema'], str):
            name = ctype['schema']
            version = None
            attributes = None
        elif isinstance(ctype['schema'], dict):
            name = ctype['schema'].get('name')
            version = ctype['schema'].get('version')
            attributes = ctype['schema'].get('attributes')
        else:
            raise ValueError('Credential type schema must be string or dict')
        if not name:
            raise ValueError("Credential type schema missing 'name'")
        if not version or not attributes:
            schema = schema_mgr.find(name, version)
            if schema:
                version = schema.version
                attributes = schema.attr_names
            else:
                raise ValueError(
                    'Schema definition not found: {} {}'.format(name, version))
        else:
            schema = Schema(name, version, attributes)
        cred_types.append({
            'description': ctype.get('description'),
            'issuer_url': ctype.get('issuer_url'),
            'schema': schema
        })
    return cred_types


class IssuerError(ExchangeError):
    """
    A message class for issues handling messages in the IssuerManager
    """
    pass


class ResolveSchemaRequest:
    """
    The message class representing an request to resolve a schema
    """
    def __init__(self, schema_name, schema_version=None, issuer_id: str = None):
        self.issuer_id = issuer_id
        self.schema_name = schema_name
        self.schema_version = schema_version


class ResolveSchemaResponse:
    """
    The message class representing the response to a schema resolution request
    """
    def __init__(self, issuer_id: str, schema, issuer_did=None):
        self.issuer_id = issuer_id
        self.schema = schema
        self.issuer_did = issuer_did


class SubmitCredRequest:
    """
    The message class representing a request to submit a credential
    """
    def __init__(self, schema_name: str, schema_version: str, attributes: Mapping, issuer_id: str = None):
        self.issuer_id = issuer_id
        self.schema_name = schema_name
        self.schema_version = schema_version
        self.attributes = attributes


class SubmitCredResponse:
    """
    The message class representing the response from a SubmitCredRequest
    """
    def __init__(self, issuer_id: str, value):
        self.issuer_id = issuer_id
        self.value = value


class IssuerService:
    """
    Manage configuration and status for a single issuer
    """
    def __init__(self, config: dict, schema_mgr: SchemaManager):
        self.api_url = None
        self.config = None
        self.cred_types = []
        self.did = None
        self.endpoint = None
        self.status = {
            'api': False,
            'ledger': False,
            'ready': False,
        }
        self.wallet_seed = None
        self.load_config(config, schema_mgr)

    def load_config(self, config: dict, schema_mgr: SchemaManager):
        self.config = config
        self.api_url = config.get('api_url')
        self.cred_types = load_cred_definitions(config.get('credential_types'), schema_mgr)
        self.endpoint = config.get('url')
        wallet = config.get('wallet')
        if wallet:
            self.wallet_seed = wallet.get('seed')

    def find_cred_type(self, schema_name: str, schema_version: str = None):
        """
        Look up a defined credential type given the schema name and version

        Args:
            schema_name: the unique schema identifier
            schema_version: the schema version number

        Returns:
            the credential type definition, if found, otherwise None
        """
        for ctype in self.cred_types:
            if ctype['schema'].name == schema_name \
                    and (not schema_version or ctype['schema'].version == schema_version):
                return ctype
        return None

    def get_ledger_config(self, manager_pid: str) -> dict:
        return {
            'endpoint': self.endpoint,
            'id': self.config['id'],
            'manager_pid': manager_pid,
            'schemas': [ctype['schema'] for ctype in self.cred_types],
            'wallet': self.config['wallet'],
        }

    def update_ledger_status(self, status: dict):
        self.did = status['did']
        self.status['ledger'] = status['synced']
        self.update_ready()

    def update_ready(self):
        self.status['ready'] = self.status['ledger'] and self.status['api']


class IssuerManager(RequestExecutor):
    """
    There should only be one instance of this class in the application.
    It is responsible for starting the issuer services and directing schema and
    credential requests to the right issuer.

    During synchronization, the IssuerManager:

        - Submits schemas and credential definitions to the ledger
        - Resolves the DID for the TheOrgBook if necessary
        - Initializes the OrgBook with our issuer information
    """

    def __init__(self, pid: str, exchange: Exchange, env: Mapping):
        super(IssuerManager, self).__init__(pid, exchange)
        self._env = env
        self._issuers = {}
        self._ledger_pid = 'indy-ledger'
        self._status = {
            'ready': False,
            'started': False,
        }
        self._sync_lock = None

    @classmethod
    def create(cls, service_mgr: ServiceManager, pid: str = 'issuer-manager'):
        """
        Initialize a standard :class:`IssuerManager` from a :class:`ServiceManager` instance

        Args:
            service_mgr: the shared :class:`ServiceManager` instance
            pid: the identifier for the :class:`IssuerManager` service

        Returns:
            the initialized :class:`IssuerManager` instance
        """
        env = service_mgr.env
        issuers = []
        issuer_ids = []
        limit_issuers = env.get('ISSUERS')
        limit_issuers = limit_issuers.split() \
            if (limit_issuers and limit_issuers != 'all') \
            else None
        config_issuers = service_mgr.services_config('issuers')
        if not config_issuers:
            raise ValueError('No issuers defined by configuration')
        for issuer_key, issuer_cfg in config_issuers.items():
            if not 'id' in issuer_cfg:
                issuer_cfg['id'] = issuer_key
            if limit_issuers is None or issuer_cfg['id'] in limit_issuers:
                issuers.append(issuer_cfg)
                issuer_ids.append(issuer_cfg['id'])
        if issuers:
            LOGGER.info('Initializing processor for services: %s', ', '.join(issuer_ids))
            mgr = cls(pid, service_mgr.exchange, env)
            for issuer_cfg in issuers:
                if 'api_url' not in issuer_cfg:
                    issuer_cfg['api_url'] = env.get('TOB_API_URL')
                svc = IssuerService(issuer_cfg, service_mgr.schema_manager)
                mgr.add_issuer(svc)
            return mgr
        else:
            raise ValueError('No defined issuers referenced by ISSUERS')

    def start(self):
        """
        Start the IssuerManager processing thread and related services
        """
        self._sync_lock = asyncio.Lock()
        ret = super(IssuerManager, self).start()
        self.run_task(self._start())
        return ret

    def add_issuer(self, issuer: IssuerService) -> None:
        self._issuers[issuer.config['id']] = issuer

    async def _start(self) -> None:
        for issuer_id, issuer in self._issuers.items():
            LOGGER.info('Registering issuer: %s', issuer_id)
            msg = indy.RegisterIssuerRequest(issuer.get_ledger_config(self.pid))
            reply = await self.submit(self._ledger_pid, msg)
            if not isinstance(reply, indy.RegisterIssuerResponse):
                raise RuntimeError('Error registering issuer {}: {}'.format(issuer_id, reply))
        self._status['started'] = True

    async def _sync(self) -> None:
        async with self._sync_lock:
            for issuer_id, issuer in self._issuers.items():
                if issuer.status['ledger'] and not issuer.status['ready']:
                    async with self._http_client(issuer_id) as http_client:
                        api_client = self._init_api_client(issuer_id)
                        cfg = issuer.config.copy()
                        cfg['did'] = issuer.did
                        cfg['credential_types'] = issuer.cred_types
                        try:
                            result = await api_client.register_issuer(http_client, cfg)
                        except TobClientError:
                            continue
                    issuer.status['ready'] = True
            self._update_status()

    def _find_issuer_for_schema(self, schema_name: str, schema_version: str = None):
        """
        Find the issuer for a particular schema and version

        Args:
            schema_name: the name of the schema as identifier on the ledger
            schema_version: the version number of the schema

        Returns:
            a tuple of the :class:`IssuerService` instance and credential type definition, or None
        """
        for issuer_id, issuer in self._issuers.items():
            cred_type = issuer.find_cred_type(schema_name, schema_version)
            if cred_type:
                return (issuer_id, cred_type)
        return None

    async def _handle_submit_cred(self, request: SubmitCredRequest, reply_to: str, ref) -> bool:
        """
        Submit a credential to the holder

        Args:
            request: a message representing the credential information

        Returns:
            the decoded JSON result of the credential submission request
        """
        errmsg = None
        if not self._status['ready']:
            errmsg = IssuerError('Issuer is not ready to accept credentials')
        elif not request.schema_name:
            errmsg = IssuerError('Missing schema name')
        elif not request.attributes:
            errmsg = IssuerError('Missing credential attributes')
        if errmsg:
            return self.send_noreply(reply_to, errmsg, ref)

        issuer_id = request.issuer_id
        if issuer_id:
            if issuer_id not in self._issuers:
                msg = IssuerError('Unknown issuer ID: {}'.format(issuer_id))
                return self.send_noreply(reply_to, msg, ref)
            cred_type = self._issuers[issuer_id].find_cred_type(
                request.schema_name, request.schema_version)
        else:
            found = self._find_issuer_for_schema(
                request.schema_name, request.schema_version)
            if found:
                issuer_id, cred_type = found
            else:
                cred_type = None

        if not cred_type:
            msg = IssuerError('Error locating credential type: {}/{}'.format(
                request.schema_name, request.schema_version))
            return self.send_noreply(reply_to, msg, ref)

        cred_data = load_cred_request(cred_type, request.attributes)
        log_json('Credential data:', cred_data, LOGGER)

        async with self._http_client(issuer_id) as http_client:
            reply = await self._store_cred(http_client, issuer_id, cred_type, cred_data)
            msg = SubmitCredResponse(issuer_id, reply)
            return self.send_noreply(reply_to, msg, ref)

    async def _store_cred(self, http_client, issuer_id: str, cred_type, cred_data) -> dict:
        """
        Submit a credential to the holder, given the credential type and data

        Args:
            http_client: the HTTP client (responsible for signing headers)
            cred_type: the credential type information
            cred_data: the prepared credential data

        Returns:
            the decoded JSON result of the credential submission request
        """
        api_client = self._init_api_client(issuer_id)

        offer_msg = indy.CredOfferRequest(issuer_id, cred_type['schema'])
        cred_offer = await self.submit(self._ledger_pid, offer_msg)
        if not isinstance(cred_offer, indy.CredOfferResponse):
            raise ValueError('Unexpected response to credential offer request: {}'.format(cred_offer))
        log_json('Created cred offer:', cred_offer.payload, LOGGER)

        cred_req = await api_client.post_json(
            http_client,
            'bcovrin/generate-claim-request',
            cred_offer.payload)
        log_json('Got cred request:', cred_req, LOGGER)

        cred_msg = indy.CredCreateRequest(cred_offer, cred_req, cred_data)
        cred = await self.submit(self._ledger_pid, cred_msg)
        if not isinstance(cred, indy.CredCreateResponse):
            raise ValueError('Unexpected response to credential creation request: {}'.format(cred))
        log_json('Created credential:', cred.payload, LOGGER)

        # Store credential
        return await api_client.post_json(
            http_client,
            'bcovrin/store-claim',
            cred.payload)

    def _init_api_client(self, issuer_id):
        """
        Initialize a TobClient instance with the required settings for this issuer

        Returns:
            the initialized TobClient instance
        """
        return TobClient(self._issuers[issuer_id].api_url)

    def _http_client(self, issuer_id=None, **kwargs):
        """
        Create a new ClientSession which includes DID signing information in each request

        Returns:
            the initialized ClientSession object
        """
        if 'request_class' not in kwargs:
            kwargs['request_class'] = SignedRequest
        if issuer_id and 'auth' not in kwargs:
            kwargs['auth'] = self._did_auth(issuer_id)
        return aiohttp.ClientSession(**kwargs)

    def _did_auth(self, issuer_id, header_list=None):
        """
        Create a :class:SignedRequestAuth representing our authentication credentials,
        used to sign outgoing requests
        """
        if issuer_id not in self._issuers:
            raise ValueError('Unknown issuer ID: {}'.format(issuer_id))
        issuer = self._issuers[issuer_id]
        if issuer.did and issuer.wallet_seed:
            key_id = 'did:sov:{}'.format(issuer.did)
            secret = issuer.wallet_seed
            if isinstance(secret, str):
                secret = secret.encode('ascii')
            return SignedRequestAuth(key_id, 'ed25519', secret, header_list)
        return None

    def process(self, message: Message) -> None:
        """
        Process a message from the exchange and send the reply, if any

        Args:
            message: The message to be processed
        """
        from_pid, request, ident = message.from_pid, message.body, message.ident

        if self._handle_response(message):
            return

        elif isinstance(request, indy.IndyIssuerStatus):
            self._issuers[request.issuer_id].update_ledger_status(request.status)
            self._update_status()
            self.run_task(self._sync())

        elif isinstance(request, ResolveSchemaRequest):
            found = self._find_issuer_for_schema(request.schema_name, request.schema_version)
            if found:
                issuer_id = found[0]
                issuer_did = self._issuers[issuer_id].did
                schema = found[1]['schema']
                msg = ResolveSchemaResponse(found[0], schema, issuer_did)
                self.send_noreply(from_pid, msg, ident)
            else:
                self.send_noreply(from_pid, IssuerError('No issuer found for schema'), ident)

        elif isinstance(request, SubmitCredRequest):
            self.run_task(self._handle_submit_cred(request, from_pid, ident))

        elif request == 'ready':
            self.send_noreply(from_pid, self._status['ready'], ident)

        elif request == 'status':
            self.send_noreply(from_pid, self._status.copy(), ident)

        else:
            raise ValueError('Unexpected message from {}: {}'.format(from_pid, request))

    def _update_status(self) -> None:
        """
        Update the overall synchronization status after an update from one issuer service
        and begin synchronization if necessary
        """
        prev_ready = self._status['ready']
        ready = True
        for issuer in self._issuers.values():
            if not issuer.status['ready']:
                ready = False
        self._status['ready'] = ready

        if ready and not prev_ready:
            LOGGER.info('Completed issuer manager initialization')
