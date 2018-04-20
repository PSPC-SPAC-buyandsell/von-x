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
import pathlib
import uuid

import aiohttp
from didauth.aiohttp import SignedRequestAuth
from didauth.indy import seed_to_did
from von_agent.agents import \
    _BaseAgent, \
    Issuer as VonIssuer, \
    HolderProver as VonHolderProver, \
    Verifier as VonVerifier
from von_agent.nodepool import NodePool
from von_agent.schemakey import schema_key_for
from von_agent.wallet import Wallet

from vonx.util import log_json

LOGGER = logging.getLogger(__name__)


class VonClient:
    def __init__(self, config=None):
        self.config = {'id': None}
        self.issuer_did = None
        self.synced = False
        self._issuer = None
        self._verifier = None
        if config:
            self.config.update(config)

    async def sync(self):
        """
        Find our DID, and initialize our schemas and claim defs on the ledger.
        """
        claim_types = self.config.get('claim_types')
        if not claim_types:
            raise ValueError("Missing issuer claims")

        wallet = self.wallet_config
        seed = wallet.get('seed')
        if not seed:
            raise ValueError('Wallet seed not defined for issuer: {}'.format(self.id))

        LOGGER.info('Init VON client %s with seed %s', self.id, seed)

        async with await self.create_issuer() as issuer:
            self.issuer_did = issuer.did
            LOGGER.info('%s issuer DID: %s', self.config['id'], self.issuer_did)

            # check DID is registered
            await self.check_registration(issuer, seed)

            # check endpoint is registered (if any)
            await self.check_endpoint(issuer)

            for claim_type in claim_types:
                await self.publish_schema(issuer, claim_type['schema'])
        self.synced = True
        LOGGER.info('VON client synced: %s', self.config['id'])

    @property
    def id(self):
        return self.config.get('id')

    @property
    def wallet_config(self):
        cfg = dict(self.config.get('wallet') or {})
        if not cfg.get('name'):
            cfg['name'] = self.id
        if not cfg.get('genesis_path'):
            cfg['genesis_path'] = self.config.get('genesis_path')
        return cfg

    @property
    def issuer_config(self):
        cfg = {}
        endpoint = self.config.get('endpoint')
        if endpoint:
            cfg['endpoint'] = endpoint
        return cfg

    async def check_genesis_path(self):
        """
        Make sure that the genesis path is defined, and download the transaction file if needed.
        """
        path = self.config.get('genesis_path')
        if not path:
            raise ValueError("Missing genesis_path")
        genesis_path = pathlib.Path(path)
        if not genesis_path.exists():
            ledger_url = self.config.get('ledger_url')
            if not ledger_url:
                raise ValueError("Cannot retrieve genesis transaction without ledger_url")
            parent_path = pathlib.Path(genesis_path.parent)
            if not parent_path.exists():
                parent_path.mkdir(parents=True)
            await self.fetch_genesis_txn(ledger_url, genesis_path)
            self.config['genesis_path'] = str(genesis_path)
        elif genesis_path.is_dir():
            raise ValueError("genesis_path must not point to a directory")
        return path

    async def fetch_genesis_txn(self, ledger_url, target_path):
        """
        Download the genesis transaction file from the ledger server.
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

    async def check_registration(self, issuer, seed=None):
        """
        Look up our nym on the ledger and register it if not present.
        """
        did = issuer.did
        LOGGER.debug('Checking DID registration %s', did)
        nym_json = await issuer.get_nym(did)
        LOGGER.debug('get_nym result for %s: %s', did, nym_json)

        nym_info = json.loads(nym_json)
        if not nym_info:
            if not self.config.get('auto_register'):
                raise RuntimeError(
                    'DID is not registered on the ledger and auto-registration disabled')

            ledger_url = self.config.get('ledger_url')
            if not ledger_url:
                raise ValueError('Cannot register DID without ledger_url')
            LOGGER.info('Registering DID %s', did)

            if not seed:
                raise ValueError('Cannot register DID on ledger without seed')

            async with aiohttp.ClientSession(read_timeout=30) as client:
                response = await client.post(
                    '{}/register'.format(ledger_url),
                    # json={'did': did, 'verkey': issuer.verkey})  - FIXME von_network needs update
                    json={'seed': seed})
                if response.status != 200:
                    raise RuntimeError(
                        'DID registration failed: {}'.format(await response.text()))
                nym_info = await response.json()
                LOGGER.debug('Registration response: %s', nym_info)
                if not nym_info or not nym_info['did']:
                    raise RuntimeError(
                        'DID registration failed: {}'.format(nym_info))

    async def check_endpoint(self, issuer):
        """
        Look up our endpoint on the ledger and register it if not present.
        """
        endpoint = self.config.get('endpoint')
        if not endpoint:
            return None
        did = issuer.did
        LOGGER.debug('Checking endpoint registration %s', endpoint)
        endp_json = await issuer.get_endpoint(did)
        LOGGER.debug('get_endpoint result for %s: %s', did, endp_json)

        endp_info = json.loads(endp_json)
        if not endp_info:
            endp_info = await issuer.send_endpoint()
            LOGGER.debug('Endpoint stored: %s', endp_info)
        return endp_info

    async def publish_schema(self, issuer, schema):
        """
        Check the ledger for a specific schema and version, and publish it if not found.
        """
        LOGGER.info('Checking for schema: %s (%s)', schema.name, schema.version)
        # Check if schema exists on ledger
        schema_json = await issuer.get_schema(
            schema_key_for({
                'origin_did': issuer.did,
                'name': schema.name,
                'version': schema.version
            }))
        ledger_schema = json.loads(schema_json)

        # If not found, send the schema to the ledger
        if ledger_schema:
            log_json('Schema found on ledger:', ledger_schema, LOGGER)
        else:
            LOGGER.info('Publishing schema: %s (%s)', schema.name, schema.version)
            schema_json = await issuer.send_schema(json.dumps({
                'name': schema.name,
                'version': schema.version,
                'attr_names': schema.attr_names}))
            ledger_schema = json.loads(schema_json)
            if not ledger_schema or not ledger_schema.get('seqNo'):
                raise RuntimeError('Schema was not published to ledger')
            log_json('Published schema:', ledger_schema, LOGGER)

        # Check if claim definition has been published
        LOGGER.info('Checking for claim def: %s (%s)', schema.name, schema.version)
        claim_def_json = await issuer.get_claim_def(
            ledger_schema['seqNo'], issuer.did)
        claim_def = json.loads(claim_def_json)

        # If claim definition is not found then publish it
        if claim_def:
            log_json('Claim def found on ledger:', claim_def, LOGGER)
        else:
            LOGGER.info('Publishing claim def: %s (%s)', schema.name, schema.version)
            claim_def_json = await issuer.send_claim_def(schema_json)
            claim_def = json.loads(claim_def_json)
            log_json('Published claim def:', claim_def, LOGGER)
        return (ledger_schema, claim_def)

    async def create_issuer(self):
        # retrieve genesis transaction if necessary
        await self.check_genesis_path()
        if not self._issuer:
            self._issuer = Agent(self.wallet_config, VonIssuer, 'Issuer', self.issuer_config)
            self._issuer.keep_open() # !! keeps the pool and wallet open for this instance
        return self._issuer

    async def create_verifier(self):
        # retrieve genesis transaction if necessary
        await self.check_genesis_path()
        if not self._verifier:
            self._verifier = Agent(self.wallet_config, VonVerifier, 'Verifier')
            # self._verifier.keep_open() # !! keeps the pool and wallet open for this instance
        return self._verifier

    async def resolve_did_from_seed(self, seed):
        #cfg = {
        #    'genesis_path': await self.check_genesis_path(),
        #    'name': 'SeedResolve',
        #    'seed': seed
        #}
        #async with Agent(cfg, _BaseAgent, 'Util') as agent:
        #    agent_did = agent.did
        #return agent_did
        return seed_to_did(seed)

    def get_did_auth(self, header_list=None):
        wallet = self.wallet_config
        seed = wallet.get('seed')
        if self.issuer_did and seed:
            secret = seed.encode('ascii')
            return SignedRequestAuth(self.issuer_did, 'ed25519', secret, header_list)


class Agent:
    def __init__(self, wallet_config, instance_cls, issuer_type, ext_cfg=None):
        if not wallet_config:
            raise ValueError('Empty wallet configuration')
        wallet_seed = wallet_config.get('seed')
        if not wallet_seed:
            raise ValueError('Missing wallet seed')
        if len(wallet_seed) != 32:
            raise ValueError('Wallet seed length is not 32 characters: {}'.format(wallet_seed))
        genesis_path = wallet_config.get('genesis_path')
        if not genesis_path:
            raise ValueError('Missing genesis_path')
        wallet_name = wallet_config.get('name')
        if not wallet_name:
            raise ValueError('Missing wallet name')

        self._pool = NodePool(
            wallet_name + '-' + issuer_type,
            genesis_path)

        self._instance_cls = instance_cls
        self._instance = None
        self._wallet = Wallet(
            self._pool,
            wallet_seed,
            wallet_name + '-' + issuer_type + '-Wallet')
        self._ext_cfg = ext_cfg
        self._opened = None
        self._keep_open = False

    def keep_open(self):
        self._keep_open = True

    async def open(self):
        if self._opened:
            return self._opened
        await self._pool.open()
        self._instance = self._instance_cls(await self._wallet.create(), self._ext_cfg)
        self._opened = await self._instance.open()
        if isinstance(self._instance, VonHolderProver):
            # seems odd
            await self._instance.create_master_secret(str(uuid.uuid4()))
        return self._opened

    async def close(self):
        if self._opened:
            await self._instance.close()
            await self._pool.close()
        self._opened = None
        self._keep_open = False

    async def __aenter__(self):
        return await self.open()

    async def __aexit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            LOGGER.exception('Exception in VON %s:', self._wallet.name)
        if not self._keep_open:
            await self.close()
