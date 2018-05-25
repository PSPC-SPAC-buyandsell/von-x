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
from typing import Mapping

import aiohttp
from didauth.ext.aiohttp import SignedRequest

from von_agent.util import SchemaKey, cred_def_id

import vonx
from vonx.services.exchange import ExchangeError, Message, RequestProcessor, RequestExecutor
from vonx.services.manager import ServiceManager
from vonx.services.schema import Schema
from vonx.services.tob import TobClient
from vonx.services.von import VonClient, resolve_did_from_seed
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


def init_issuer_manager(service_manager: ServiceManager, pid: str = 'issuer-manager'):
    """
    Initialize a standard IssuerManager from a ServiceManager instance

    Args:
        service_manager: the shared :class:`ServiceManager` instance
        pid: the identifier for the :class:`IssuerManager` service

    Returns:
        the initialized :class:`IssuerManager` instance
    """
    env = service_manager.env
    issuers = []
    issuer_ids = []
    limit_issuers = env.get('ISSUERS')
    limit_issuers = limit_issuers.split() \
        if (limit_issuers and limit_issuers != 'all') \
        else None
    config_issuers = service_manager.services_config('issuers')
    if not config_issuers:
        raise ValueError('No issuers defined by configuration')
    for issuer_key, issuer in config_issuers.items():
        if not 'id' in issuer:
            issuer['id'] = issuer_key
        if limit_issuers is None or issuer['id'] in limit_issuers:
            issuers.append(issuer)
            issuer_ids.append(issuer['id'])
    if issuers:
        LOGGER.info('Initializing processor for services: %s', ', '.join(issuer_ids))
        return IssuerManager(service_manager, pid, issuers)
    else:
        raise ValueError('No defined issuers referenced by ISSUERS')



class IssuerError(ExchangeError):
    """
    A generic Exception for problems with an IssuerService
    """
    pass


class IssuerStatus:
    """
    The message class representing an IssuerService status response
    """
    def __init__(self, status):
        self.value = status


class ResolveSchemaRequest:
    """
    The message class representing an request to resolve a schema
    """
    def __init__(self, schema_name, schema_version=None):
        self.schema_name = schema_name
        self.schema_version = schema_version


class ResolveSchemaResponse:
    """
    The message class representing the response to a schema resolution request
    """
    def __init__(self, schema, pid, did):
        self.schema = schema
        self.issuer_pid = pid
        self.issuer_did = did


class SubmitCredRequest:
    """
    The message class representing a request to submit a credential
    """
    def __init__(self, schema_name, schema_version, attributes):
        self.schema_name = schema_name
        self.schema_version = schema_version
        self.attributes = attributes


class SubmitCredResponse:
    """
    The message class representing the response from a SubmitCredRequest
    """
    def __init__(self, value):
        self.value = value


class IssuerService(RequestExecutor):
    """
    The IssuerService handles issuer initialization as well as processing of credential
    submission and other requests surrounding the ledger or TheOrgBook services. It listens
    for requests on the exchange and performs each one in a thread pool.

    During synchronization it:

        - Resolves the DID for the TheOrgBook if necessary
        - Submits schemas and credential definitions to the ledger
        - Initializes the OrgBook with our issuer information

    These instances are normally initialized by the IssuerManager.
    """

    def __init__(self, service_mgr: ServiceManager, spec=None, manager_pid=None):
        self._pid = None
        self._cred_types = []
        self._config = {}
        self._did_auth = None
        self._status = {}
        self._service_mgr = service_mgr
        self._manager_pid = manager_pid
        self._api_did = None
        self._update_config(spec)
        self._von_client = None

        super(IssuerService, self).__init__(self._pid, service_mgr.exchange)
        self._init_status()

    def _update_config(self, spec) -> None:
        """
        Load configuration settings
        """
        if spec:
            self._config.update(spec)
        if 'id' in self._config:
            self._pid = self._config['id']
        if 'did' in self._config:
            self._status['did'] = self._config['did']
        if 'api_did' in self._config:
            self._api_did = self._config['api_did']
        if 'credential_types' in spec:
            self._load_cred_types(spec['credential_types'])
            self._config['credential_types'] = self._cred_types

    def _init_status(self) -> None:
        self._update_status({
            'id': self._pid,
            'did': None,
            'ledger': False,
            'orgbook': False,
            'ready': False,
            'syncing': False,
            'started': False,
        })

    def _update_status(self, update=None, silent=False) -> None:
        """
        Alert the manager for this issuer that the sync status has been updated
        """
        if update:
            self._status.update(update)
        if self._manager_pid and not silent:
            self.send_noreply(self._manager_pid, IssuerStatus(self._status))

    def _load_cred_types(self, values) -> None:
        """
        Load the credential types defined by our config into a standard format
        """
        schema_mgr = self._service_mgr.schema_manager
        for ctype in values:
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
            self._cred_types.append({
                'description': ctype.get('description'),
                'issuer_url': ctype.get('issuer_url'),
                'schema': schema
            })

    @property
    def api_did(self) -> str:
        """
        Accessor for the DID used to access TheOrgBook
        """
        return self._api_did

    @api_did.setter
    def api_did(self, did: str) -> None:
        """
        Setter for the DID used to access TheOrgBook
        """
        self._api_did = did

    def ready(self) -> bool:
        """
        Check whether the issuer is prepared to accept credentials and proof requests
        """
        return self._status['ready']

    def status(self) -> dict:
        """
        Get current sync status
        """
        return self._status.copy()

    def start(self):
        """
        Start a thread to listen for incoming messages, and perform any pre-sync setup
        """
        ret = super(IssuerService, self).start()
        self.run_task(self._start())
        return ret

    async def _start(self):
        """
        Perform any pre-sync setup and let the manager process know we've started
        """
        if self._status['started']:
            return
        try:
            await self._resolve_api_did()
            self._update_status({
                'started': True
            })
        except ValueError as e:
            if self._manager_pid:
                errmsg = IssuerError(str(e))
                self.send_noreply(self._manager_pid, errmsg)

    async def _resolve_api_did(self) -> str:
        """
        Resolve the DID for TheOrgBook from given a seed if necessary.
        This action is performed once at startup.

        Returns:
            the DID of the service
        """
        if not self._api_did:
            env = self._service_mgr.env
            tob_did = env.get('TOB_INDY_DID')
            if not tob_did:
                tob_seed = env.get('TOB_INDY_SEED')
                if not tob_seed:
                    raise ValueError('Either TOB_INDY_SEED or TOB_INDY_DID must be defined')
                LOGGER.info('Resolving TOB DID from seed %s', tob_seed)
                tob_did = await resolve_did_from_seed(tob_seed)
                if not tob_did:
                    raise ValueError('DID for TOB could not be resolved')
                LOGGER.info('Resolved TOB DID to %s', tob_did)
            self._api_did = tob_did
        return self._api_did

    async def _sync(self):
        """
        Perform the initial synchronization process with both the ledger (VonClient)
        and TheOrgBook (TobClient)
        """
        #pylint: disable=broad-except
        self._update_status({
            'syncing': True
        })
        try:
            von_client = self.init_von_client()
            await von_client.sync()
            self._update_status({
                'did': von_client.issuer_did,
                'ledger': von_client.synced
            })
            if von_client.synced:
                self._did_auth = von_client.get_did_auth()
                tob_client = self.init_tob_client()
                async with self.http as http_client:
                    await tob_client.sync(http_client)
                self._update_status({
                    'orgbook': tob_client.synced
                })
            if self._status['ledger'] and self._status['orgbook']:
                self._update_status({'ready': True, 'syncing': False})
            return self._status['ready']
        except Exception:
            self._update_status({'ready': False, 'syncing': False})
            raise

    def http_client(self, *args, **kwargs):
        """
        Create a new ClientSession which includes DID signing information in each request

        Returns:
            the initialized ClientSession object
        """
        if 'request_class' not in kwargs:
            kwargs['request_class'] = SignedRequest
        if self._did_auth and 'auth' not in kwargs:
            kwargs['auth'] = self._did_auth
        return aiohttp.ClientSession(*args, **kwargs)

    @property
    def did_auth(self):
        """
        Accessor for the aiohttp-compatible DID signer
        """
        return self._did_auth

    def init_von_client(self):
        """
        Initialize a VonClient instance with the required settings for this issuer

        Returns:
            the initialized VonClient instance
        """
        if not self._von_client:
            cfg = self._config.copy()
            self._von_client = VonClient(cfg)
        return self._von_client

    def init_tob_client(self):
        """
        Initialize a TobClient instance with the required settings for this issuer

        Returns:
            the initialized TobClient instance
        """
        cfg = self._config.copy()
        cfg['did'] = self._status['did']
        return TobClient(cfg)

    def find_cred_type_for_schema(self, schema_name: str, schema_version: str = None):
        """
        Look up a defined credential type given the schema name and version

        Args:
            schema_name: the unique schema identifier
            schema_version: the schema version number

        Returns:
            the credential type definition, if found, otherwise None
        """
        for ctype in self._cred_types:
            if ctype['schema'].name == schema_name \
                    and (not schema_version or ctype['schema'].version == schema_version):
                return ctype
        return None

    def process(self, message: Message) -> None:
        """
        Process a message from the exchange by running a task in the executor

        Args:
            message: The message received
        """
        self.run_task(self.handle_request(message))

    async def handle_request(self, message: Message) -> bool:
        """
        Handle a single message from the exchange and send the reply if any

        Args:
            message: The message received
        """
        #pylint: disable=broad-except
        try:
            from_pid, request, ident = message.from_pid, message.body, message.ident
            if isinstance(request, SubmitCredRequest):
                try:
                    result = await self.submit_cred(
                        request.schema_name,
                        request.schema_version,
                        request.attributes)
                    return self.send_noreply(from_pid, SubmitCredResponse(result), ident)
                except Exception:
                    errmsg = IssuerError('Exception during credential submission')
                    self.send_noreply(from_pid, errmsg, ident)
            elif request == 'sync':
                await self._sync()
                return True
            elif request == 'ready':
                return self.send_noreply(from_pid, self.ready(), ident)
            elif request == 'status':
                return self.send_noreply(from_pid, self.status(), ident)
            else:
                raise ValueError('Unrecognized request type')
        except Exception:
            errmsg = IssuerError('Exception during issuer request handling')
            return self.send_noreply(from_pid, errmsg, ident)

    async def _get_issuer_cred_def(self, issuer, schema: Schema):
        """
        Create a credential definition for a given issuer and schema

        Args:
            issuer: an instance of the issuer agent created by VonAgent
            schema: the schema definition used by this credential definition

        Returns:
            a tuple of the ledger schema definition and the new credential definition JSON
        """
        LOGGER.debug('Retrieving ledger schema: %s', schema)

        # We need schema from ledger
        schema_json = await issuer.get_schema(
            SchemaKey(
                origin_did=issuer.did,
                name=schema.name,
                version=schema.version
            ))
        ledger_schema = json.loads(schema_json)

        log_json('Found ledger schema:', ledger_schema, LOGGER)

        cred_def_json = await issuer.get_cred_def(
            cred_def_id(issuer.did, ledger_schema['seqNo']))
        return (ledger_schema, cred_def_json)

    async def store_cred(self, http_client, cred_type, cred_data):
        """
        Submit a credential to the holder, given the credential type and data

        Args:
            http_client: the HTTP client (responsible for signing headers)
            cred_type: the credential type information
            cred_data: the prepared credential data

        Returns:
            the decoded JSON result of the credential submission request
        """
        #pylint: disable=too-many-locals
        von_client = self.init_von_client()
        tob_client = self.init_tob_client()

        async with await von_client.create_issuer() as von_issuer:
            (ledger_schema, cred_def_json) = await self._get_issuer_cred_def(
                von_issuer,
                cred_type['schema'])

            # We create a cred offer
            LOGGER.info('Creating cred offer for TOB at DID %s', self._api_did)
            cred_offer_json = await von_issuer.create_cred_offer(ledger_schema['seqNo'])
            cred_offer = json.loads(cred_offer_json)

            log_json('Requesting cred request:', {
                'claim_offer': cred_offer,
                'claim_def': json.loads(cred_def_json)
            }, LOGGER)

            cred_req = await tob_client.post_json(
                http_client,
                'bcovrin/generate-claim-request',
                {
                    'claim_offer': cred_offer_json,
                    'claim_def': cred_def_json
                })
            log_json('Got cred request:', cred_req, LOGGER)

            cred_request = cred_req['credential_request']
            cred_request_metadata = cred_req['credential_request_metadata_json']

            (cred_json, _cred_revoc_id) = await von_issuer.create_cred(
                cred_offer_json,
                cred_request,
                cred_data)

            issuer_did = von_issuer.did

        cred = json.loads(cred_json)
        log_json('Created credential:', cred, LOGGER)

        # Store credential
        return await tob_client.post_json(
            http_client,
            'bcovrin/store-claim',
            {
                'claim_type': cred_type['schema'].name,
                'claim_data': cred,
                'issuer_did': issuer_did,
                'cred_def': json.loads(cred_def_json),
                'cred_req_metadata': cred_request_metadata,
            })

    async def submit_cred(self, schema_name: str, schema_version: str, attribs: Mapping) -> dict:
        """
        Submit a credential to the holder

        Args:
            schema_name: the name of the schema registered on the ledger
            schema_version: the schema version
            attribs: a dictionary of credential attributes

        Returns:
            the decoded JSON result of the credential submission request
        """
        if not self.ready():
            raise RuntimeError('Issuer service is not ready')
        if not schema_name:
            raise ValueError('Missing schema name')
        if not attribs:
            raise ValueError('Missing request data')
        if not self._api_did:
            raise ValueError('Missing DID for TOB')
        cred_type = self.find_cred_type_for_schema(schema_name, schema_version)
        if not cred_type:
            raise RuntimeError('Error locating credential type')

        cred_data = load_cred_request(cred_type, attribs)
        log_json('Credential data:', cred_data, LOGGER)

        async with self.http as http_client:
            return await self.store_cred(http_client, cred_type, cred_data)


class IssuerManager(RequestProcessor):
    """
    There should only be one instance of this class in the application.
    It is responsible for starting the issuer services and directing schema requests
    to the right issuer.
    """

    def __init__(self, service_mgr: ServiceManager, pid: str, issuer_specs):
        super(IssuerManager, self).__init__(pid, service_mgr.exchange)
        self._env = service_mgr.env
        self._issuers = {}
        self._issuer_specs = issuer_specs
        self._issuer_status = {}
        self._parallel_sync = not self._env.get('PARALLEL_SYNC', True)
        self._service_mgr = service_mgr
        self._ready = False
        self._started = False

    def ready(self) -> bool:
        """
        Check if the IssuerManager and all services are ready for credentials and proofs
        """
        return self._ready

    def status(self) -> dict:
        """
        Fetch the status of the IssuerManager and its IssuerServices
        """
        return {
            'issuers': self._issuer_status.copy(),
            'ready': self._ready,
            'started': self._started,
            'version': vonx.__version__
        }

    def start(self):
        """
        Start the IssuerManager processing thread and related services
        """
        self._init_services()
        ret = super(IssuerManager, self).start()
        self._start_services()
        return ret

    def stop(self, wait=True) -> None:
        """
        Stop related services as well as the message processing thread
        """
        self._stop_services()
        super(IssuerManager, self).stop(wait)

    def _init_services(self) -> None:
        """
        Initialize all services
        """
        self._init_issuers()

    def _start_services(self) -> None:
        """
        Fetch the DID for TheOrgBook if necessary, and start all issuer services
        """
        self._start_issuers()

    def _stop_services(self):
        """
        Stop all services
        """
        self._stop_issuers()

    @property
    def issuer_specs(self) -> list:
        """
        Accessor for the set of issuer specifications loaded from the configuration
        """
        return self._issuer_specs

    @property
    def ledger_url(self) -> str:
        """
        Accessor for the ledger URL
        """
        return self._env.get('INDY_LEDGER_URL')

    def extend_issuer_spec(self, spec: dict) -> dict:
        """
        Given an issuer specification, return the extended specification
        with default values inserted for undefined properties

        Args:
            spec: the raw issuer specification

        Returns:
            the updated issuer specification
        """
        spec = spec.copy() if spec else {}
        if not 'auto_register' in spec:
            spec['auto_register'] = self._env.get('AUTO_REGISTER_DID')
        if not 'genesis_path' in spec:
            spec['genesis_path'] = self._env.get('INDY_GENESIS_PATH')
        if not 'ledger_url' in spec:
            spec['ledger_url'] = self.ledger_url
        if not 'api_url' in spec:
            spec['api_url'] = self._env.get('TOB_API_URL')
        return spec

    def init_von_client(self):
        """
        Create a VonClient instance from our configuration

        Returns:
            the initialized VonClient instance
        """
        cfg = {
            'genesis_path': self._env.get('INDY_GENESIS_PATH'),
            'ledger_url': self.ledger_url
        }
        return VonClient(cfg)

    def _init_issuers(self) -> None:
        """
        Initialize issuer services from the shared configuration
        """
        for spec in self._issuer_specs:
            service = IssuerService(
                self._service_mgr,
                self.extend_issuer_spec(spec),
                self.pid)
            self._issuers[service.pid] = service

    def _start_issuers(self) -> None:
        """
        Start all defined issuer services. After each service has started, the initial sync
        process will be triggered
        """
        LOGGER.info('Starting issuers')
        for _id, service in self._issuers.items():
            service.start()

    def _stop_issuers(self) -> None:
        """
        Stop all defined issuer services
        """
        for _id, service in self._issuers.items():
            service.stop()

    def find_issuer_for_schema(self, schema_name: str, schema_version: str = None):
        """
        Find the issuer for a particular schema and version

        Args:
            schema_name: the name of the schema as identifier on the ledger
            schema_version: the version number of the schema

        Returns:
            a tuple of the :class:`IssuerService` instance and credential type definition, or None
        """
        for _id, service in self._issuers.items():
            cred_type = service.find_cred_type_for_schema(schema_name, schema_version)
            if cred_type:
                return (service, cred_type)
        return None

    def process(self, message: Message) -> None:
        """
        Process a message from the exchange and send the reply, if any

        Args:
            message: The message to be processed
        """
        from_pid, request, ident, ref = message.from_pid, message.body, message.ident, message.ref

        if isinstance(request, IssuerError):
            LOGGER.error(request.format())
        elif isinstance(request, IssuerStatus):
            self._update_issuer_status(from_pid, request.value)
        elif isinstance(request, ResolveSchemaRequest):
            found = self.find_issuer_for_schema(request.schema_name, request.schema_version)
            if found:
                issuer_pid = found[0].pid
                issuer_did = self._issuer_status.get(issuer_pid, {}).get('did')
                schema = found[1]['schema']
                msg = ResolveSchemaResponse(schema, issuer_pid, issuer_did)
                self.send_noreply(from_pid, msg, ident)
            else:
                self.send_noreply(from_pid, IssuerError('No issuer found for schema'), ident)
        elif isinstance(request, SubmitCredRequest):
            # need to find the issuer service and forward the request there
            found = self.find_issuer_for_schema(request.schema_name, request.schema_version)
            if found:
                self.send(found[0].pid, ident, request, ref, from_pid)
            else:
                self.send_noreply(from_pid, IssuerError('No issuer found for schema'), ident)
        elif request == 'ready':
            self.send_noreply(from_pid, self.ready(), ident)
        elif request == 'status':
            self.send_noreply(from_pid, self.status(), ident)
        else:
            raise ValueError('Unexpected message from {}: {}'.format(from_pid, request))

    def _update_issuer_status(self, pid: str, status: dict) -> None:
        """
        Update the overall synchronization status after an update from one issuer service
        and begin synchronization if necessary
        """
        prev_status = self._issuer_status.get(pid, {})
        self._issuer_status[pid] = status

        prev_started = self._started
        prev_ready = self._ready
        started = True
        ready = True
        unsynced = None
        for service_id, _service in self._issuers.items():
            if not self._issuer_status.get(service_id, {}).get('started'):
                started = False
            if not self._issuer_status.get(service_id, {}).get('ready'):
                ready = False
                if not unsynced and not self._issuer_status.get(service_id, {}).get('syncing'):
                    unsynced = service_id
        self._started = started
        self._ready = ready

        if self._parallel_sync:
            if not prev_status.get('synced') and status.get('synced'):
                self.send_noreply(pid, 'sync')
        elif (started and not prev_started) or (status.get('ready') and not prev_status.get('ready')):
            if unsynced:
                self.send_noreply(unsynced, 'sync')

        if ready and not prev_ready:
            LOGGER.info('Completed issuer manager initialization')
