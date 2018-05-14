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

import aiohttp
from didauth.ext.aiohttp import SignedRequest

from von_agent.codec import cred_attr_value
from von_agent.util import SchemaKey, cred_def_id

import vonx
from vonx.services import eventloop
from vonx.services.exchange import ExchangeError, RequestProcessor, RequestExecutor
from vonx.services.manager import ServiceManager
from vonx.services.schema import Schema
from vonx.services.tob import TobClient
from vonx.services.von import VonClient
from vonx.util import log_json

LOGGER = logging.getLogger(__name__)


#def claim_value_pair(plain):
#    return [str(plain), encode(plain)]
#
#
#def encode_claim(claim):
#    encoded_claim = {}
#    for key, value in claim.items():
#        encoded_claim[key] = claim_value_pair(value) if value else \
#            claim_value_pair("")
#    return encoded_claim
#
#
def load_cred_request(claim_type, request):
    cred = {}
    for attr in claim_type['schema'].attr_names:
        cred[attr] = request.get(attr)
    claim_type['schema'].validate(cred)
    return cred


def init_issuer_manager(service_manager: ServiceManager, pid='issuer-manager'):
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
    pass


class IssuerStatus:
    def __init__(self, status):
        self.value = status


class ResolveSchemaRequest:
    def __init__(self, schema_name, schema_version=None):
        self.schema_name = schema_name
        self.schema_version = schema_version


class SubmitClaimRequest:
    def __init__(self, schema_name, schema_version, attributes):
        self.schema_name = schema_name
        self.schema_version = schema_version
        self.attributes = attributes


class SubmitClaimResponse:
    def __init__(self, value):
        self.value = value


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
        self._orgbook_did = None
        self._service_mgr = service_mgr
        self._ready = False
        #self._init_services()

    def ready(self):
        return self._ready

    def status(self):
        return {
            'issuers': self._issuer_status.copy(),
            'orgbook_did': self._orgbook_did,
            'ready': self._ready,
            'version': vonx.__version__
        }

    def start(self):
        self._init_services()
        ret = super(IssuerManager, self).start()
        self._start_services()
        return ret

    def stop(self, wait=True):
        self._stop_services()
        super(IssuerManager, self).stop(wait)

    def _init_services(self):
        self._init_issuers()

    def _start_services(self):
        #pylint: disable=broad-except
        async def resolve():
            try:
                await self.resolve_orgbook_did()
            except Exception:
                errmsg = IssuerError('Error while resolving DID for TOB', True)
                self.send_noreply(self.pid, errmsg)
                raise
            try:
                await self._start_issuers()
            except Exception:
                errmsg = IssuerError('Error while starting issuer services', True)
                self.send_noreply(self.pid, errmsg)
                raise
        eventloop.run_in_thread(resolve())

    def _stop_services(self):
        self._stop_issuers()

    # Resolve DID for orgbook from given seed if necessary
    async def resolve_orgbook_did(self):
        if not self._orgbook_did:
            tob_did = self._env.get('TOB_INDY_DID')
            if not tob_did:
                tob_seed = self._env.get('TOB_INDY_SEED')
                if not tob_seed:
                    raise ValueError('Either TOB_INDY_SEED or TOB_INDY_DID must be defined')
                LOGGER.info('Resolving TOB DID from seed %s', tob_seed)
                # create 'blank' client with no issuer information
                von_client = self.init_von_client()
                tob_did = await von_client.resolve_did_from_seed(tob_seed)
                if not tob_did:
                    raise ValueError('DID for TOB could not be resolved')
                self._orgbook_did = tob_did
                LOGGER.info('Resolved TOB DID to %s', tob_did)
        return self._orgbook_did

    @property
    def issuer_specs(self):
        return self._issuer_specs

    def get_ledger_url(self):
        return self._env.get('INDY_LEDGER_URL')

    def extend_issuer_spec(self, spec):
        spec = spec.copy() if spec else {}
        if not 'auto_register' in spec:
            spec['auto_register'] = self._env.get('AUTO_REGISTER_DID')
        if not 'genesis_path' in spec:
            spec['genesis_path'] = self._env.get('INDY_GENESIS_PATH')
        if not 'ledger_url' in spec:
            spec['ledger_url'] = self.get_ledger_url()
        if not 'api_url' in spec:
            spec['api_url'] = self._env.get('TOB_API_URL')
        spec['api_did'] = self._orgbook_did
        return spec

    def init_von_client(self):
        cfg = {
            'genesis_path': self._env.get('INDY_GENESIS_PATH'),
            'ledger_url': self.get_ledger_url()
        }
        return VonClient(cfg)

    def _init_issuers(self):
        for spec in self._issuer_specs:
            service = IssuerService(
                self._service_mgr,
                self.extend_issuer_spec(spec),
                self.pid)
            self._issuers[service.pid] = service

    async def _start_issuers(self):
        sequential = not self._env.get('PARALLEL_SYNC', True)
        LOGGER.info('Starting issuers %s', (sequential and ' (sequentially)' or ''))
        for _id, service in self._issuers.items():
            service.set_api_did(self._orgbook_did)
            if sequential:
                await service.start(True)
            else:
                # run init in a separate thread
                service.start()

    def _stop_issuers(self):
        for _id, service in self._issuers.items():
            service.stop()

    def find_issuer_for_schema(self, schema_name, schema_version=None):
        for _id, service in self._issuers.items():
            claim_type = service.find_claim_type_for_schema(schema_name, schema_version)
            if claim_type:
                return (service, claim_type)
        return None

    def process(self, from_pid, ident, message, ref):
        if isinstance(message, IssuerError):
            LOGGER.error(message.format())
        elif isinstance(message, IssuerStatus):
            self._issuer_status[from_pid] = message.value
            self.update_status()
        elif isinstance(message, ResolveSchemaRequest):
            found = self.find_issuer_for_schema(message.schema_name, message.schema_version)
            if found:
                self.send_noreply(from_pid, found[0].pid, ident)
            else:
                self.send_noreply(from_pid, IssuerError('No issuer found for schema'), ident)
        elif isinstance(message, SubmitClaimRequest):
            # need to find the issuer service and forward the request there
            found = self.find_issuer_for_schema(message.schema_name, message.schema_version)
            if found:
                self.send(found[0].pid, ident, message, ref, from_pid)
            else:
                self.send_noreply(from_pid, IssuerError('No issuer found for schema'), ident)
        elif message == 'ready':
            self.send_noreply(from_pid, self.ready(), ident)
        elif message == 'status':
            self.send_noreply(from_pid, self.status(), ident)
        else:
            raise ValueError('Unexpected message from {}: {}'.format(from_pid, message))

    def update_status(self):
        ok = True
        old_ok = self._ready
        for service_id, _service in self._issuers.items():
            if not self._issuer_status.get(service_id, {}).get('ready'):
                ok = False
                break
        self._ready = ok
        if ok and not old_ok:
            LOGGER.info('Completed issuer manager initialization')


class IssuerService(RequestExecutor):
    """
    The IssuerService handles issuer initialization as well as processing of claim
    submission and other requests surrounding the ledger or OrgBook services. It listens
    for requests on the exchange and performs each one in a thread pool.
    During synchronization it:
        - Resolves the DID for the OrgBook if necessary
        - Submits schemas and claim definitions to the ledger
        - Initializes the OrgBook with our issuer information
    These instances are normally initialized by the InstanceManager.
    """

    def __init__(self, service_mgr: ServiceManager, spec=None, manager_pid=None):
        self._pid = None
        self._claim_types = []
        self._config = {}
        self._did_auth = None
        self._status = {}
        self._service_mgr = service_mgr
        self._manager_pid = manager_pid
        self._orgbook_did = None
        self._update_config(spec)
        self._von_client = None

        super(IssuerService, self).__init__(self._pid, service_mgr.exchange)
        self._update_status({
            'id': self._pid,
            'did': None,
            'ledger': False,
            'orgbook': False,
            'ready': False,
            'syncing': False
        })

    def _update_config(self, spec):
        if spec:
            self._config.update(spec)
        if 'id' in self._config:
            self._pid = self._config['id']
        if 'did' in self._config:
            self._status['did'] = self._config['did']
        if 'api_did' in self._config:
            self._orgbook_did = self._config['api_did']
        if 'claim_types' in spec:
            self._load_claim_types(spec['claim_types'])
            self._config['claim_types'] = self._claim_types

    def set_api_did(self, did):
        self._orgbook_did = did

    def _update_status(self, update=None, silent=False):
        if update:
            self._status.update(update)
        if self._manager_pid and not silent:
            self.send_noreply(self._manager_pid, IssuerStatus(self._status))

    def _load_claim_types(self, values):
        schema_mgr = self._service_mgr.schema_manager
        for ctype in values:
            if 'schema' not in ctype:
                raise ValueError("Claim type must define 'schema'")
            if isinstance(ctype['schema'], str):
                name = ctype['schema']
                version = None
                attributes = None
            elif isinstance(ctype['schema'], dict):
                name = ctype['schema'].get('name')
                version = ctype['schema'].get('version')
                attributes = ctype['schema'].get('attributes')
            else:
                raise ValueError('Claim type schema must be string or dict')
            if not name:
                raise ValueError("Claim type schema missing 'name'")
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
            self._claim_types.append({
                'description': ctype.get('description'),
                'issuer_url': ctype.get('issuer_url'),
                'schema': schema
            })

    def ready(self):
        return self._status['ready']

    def start(self, as_coro=False):
        #pylint: disable=broad-except
        try:
            ret = super(IssuerService, self).start()
            async def init():
                try:
                    await self.sync()
                except Exception:
                    if self._manager_pid:
                        errmsg = IssuerError('Exception during issuer sync', True)
                        self.send_noreply(self._manager_pid, errmsg)
                    else:
                        LOGGER.exception('Exception during issuer sync:')
            # Start another thread to perform initial sync
            coro = init()
            if as_coro:
                return coro
            self.run_task(coro)
            return ret
        except Exception:
            LOGGER.exception('Error starting issuer service:')

    # Sync with issuer VON client, then TOB client
    async def sync(self):
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
        if 'request_class' not in kwargs:
            kwargs['request_class'] = SignedRequest
        if self._did_auth and not 'auth' in kwargs:
            kwargs['auth'] = self._did_auth
        return aiohttp.ClientSession(*args, **kwargs)

    def did_auth(self):
        return self._did_auth

    def init_von_client(self):
        if not self._von_client:
            cfg = self._config.copy()
            self._von_client = VonClient(cfg)
        return self._von_client

    def init_tob_client(self):
        cfg = self._config.copy()
        cfg['did'] = self._status['did']
        return TobClient(cfg)

    def find_claim_type_for_schema(self, schema_name, schema_version=None):
        for ctype in self._claim_types:
            if ctype['schema'].name == schema_name \
                    and (not schema_version or ctype['schema'].version == schema_version):
                return ctype
        return None

    def process(self, from_pid, ident, message, ref):
        self.run_task(self.handle_request(from_pid, ident, message))

    async def handle_request(self, from_pid, ident, message):
        #pylint: disable=broad-except
        try:
            if isinstance(message, SubmitClaimRequest):
                try:
                    result = await self.submit_claim(
                        message.schema_name,
                        message.schema_version,
                        message.attributes)
                    return self.send_noreply(from_pid, SubmitClaimResponse(result), ident)
                except Exception:
                    errmsg = IssuerError('Exception during claim submission', True)
                    self.send_noreply(from_pid, errmsg, ident)
            else:
                raise ValueError('Unrecognized request type')
        except Exception:
            errmsg = IssuerError('Exception during issuer request handling', True)
            return self.send_noreply(from_pid, errmsg, ident)

    async def _create_issuer_cred_def(self, issuer, schema: Schema):
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

    async def store_cred(self, http_client, claim_type, cred_data):
        #pylint: disable=too-many-locals
        von_client = self.init_von_client()
        tob_client = self.init_tob_client()

        async with await von_client.create_issuer() as von_issuer:
            (ledger_schema, cred_def_json) = await self._create_issuer_cred_def(
                von_issuer,
                claim_type['schema'])

            # We create a cred offer
            schema_json = json.dumps(ledger_schema)
            LOGGER.info('Creating cred offer for TOB at DID %s', self._orgbook_did)
            cred_offer_json = await von_issuer.create_cred_offer(ledger_schema['seqNo'])
            cred_offer = json.loads(cred_offer_json)

            log_json('Requesting cred request:', {
                'cred_offer': cred_offer,
                'cred_def': json.loads(cred_def_json)
            }, LOGGER)

            cred_req = await tob_client.post_json(
                http_client,
                'bcovrin/generate-credential-request',
                {
                    'cred_offer': cred_offer_json,
                    'cred_def': cred_def_json
                })
            log_json('Got cred request:', cred_req, LOGGER)

            cred_request_json = json.dumps(cred_req['request'])
            #cred_request_metadata_json = json.dumps(cred_req['metadata'])

            (cred_json, _cred_revoc_id, _rev_reg_delta_json) = await von_issuer.create_cred(
                cred_offer_json,
                cred_request_json,
                cred_data)

        cred = json.loads(cred_json)
        log_json('Created credential:', cred, LOGGER)

        # Store credential
        return await tob_client.post_json(
            http_client,
            'bcovrin/store-credential',
            {
                'cred_req': cred_req,
                'cred_data': cred
            })

    async def submit_claim(self, schema_name, schema_version, attribs):
        if not self.ready():
            raise RuntimeError('Issuer service is not ready')
        if not schema_name:
            raise ValueError('Missing schema name')
        if not attribs:
            raise ValueError('Missing request data')
        if not self._orgbook_did:
            raise ValueError('Missing DID for TOB')
        claim_type = self.find_claim_type_for_schema(schema_name, schema_version)
        if not claim_type:
            raise RuntimeError('Error locating claim type')

        cred_data = load_cred_request(claim_type, attribs)
        log_json('Credential data:', cred_data, LOGGER)

        async with self.http as http_client:
            return await self.store_cred(http_client, claim_type, cred_data)
