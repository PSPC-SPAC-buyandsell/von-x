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
from von_agent.agents import \
    _BaseAgent, \
    Issuer as VonIssuer, \
    HolderProver as VonHolderProver, \
    Verifier as VonVerifier
from von_agent.nodepool import NodePool
from von_agent.schemakey import schema_key_for
from von_agent.wallet import Wallet

from app.util import log_json

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

        LOGGER.info('Init VON client %s with seed %s',
                    self.config['id'],
                    self.config.get('wallet_seed'))
        async with await self.create_issuer() as issuer:
            self.issuer_did = issuer.did
            LOGGER.info('%s issuer DID: %s', self.config['id'], self.issuer_did)
            for claim_type in claim_types:
                schema_def = {
                    'name': claim_type['schema']['name'],
                    'version': claim_type['schema']['version'],
                    'attr_names': claim_type['schema']['attributes']
                }
                await self.publish_schema(issuer, schema_def)
        self.synced = True
        LOGGER.info('VON client synced: %s', self.config['id'])

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

    async def publish_schema(self, issuer, schema):
        """
        Check the ledger for a specific schema and version, and publish it if not found.
        """
        # Check if schema exists on ledger
        schema_json = await issuer.get_schema(
            schema_key_for({
                'origin_did': issuer.did,
                'name': schema['name'],
                'version': schema['version']
            }))
        ledger_schema = json.loads(schema_json)

        # If not found, send the schema to the ledger
        if ledger_schema:
            log_json('Schema found on ledger:', ledger_schema, LOGGER)
        else:
            schema_json = await issuer.send_schema(json.dumps(schema))
            ledger_schema = json.loads(schema_json)
            if not ledger_schema or not ledger_schema.get('seqNo'):
                raise RuntimeError('Schema was not published to ledger, check DID is registered')
            log_json('Published schema:', ledger_schema, LOGGER)

        # Check if claim definition has been published
        claim_def_json = await issuer.get_claim_def(
            ledger_schema['seqNo'], issuer.did)
        claim_def = json.loads(claim_def_json)

        # If claim definition is not found then publish it
        if claim_def:
            log_json('Claim def found on ledger:', claim_def, LOGGER)
        else:
            claim_def_json = await issuer.send_claim_def(schema_json)
            claim_def = json.loads(claim_def_json)
            log_json('Published claim def:', claim_def, LOGGER)
        return (ledger_schema, claim_def)

    async def create_issuer(self):
        # retrieve genesis transaction if necessary
        await self.check_genesis_path()
        if not self._issuer:
            self._issuer = Agent(self.config, VonIssuer, 'Issuer')
            self._issuer.keep_open() # !! keeps the pool and wallet open for this instance
        return self._issuer

    async def create_verifier(self):
        # retrieve genesis transaction if necessary
        await self.check_genesis_path()
        if not self._verifier:
            self._verifier = Agent(self.config, VonVerifier, 'Verifier')
            # self._verifier.keep_open() # !! keeps the pool and wallet open for this instance
        return self._verifier

    async def resolve_did_from_seed(self, seed):
        cfg = {
            'genesis_path': await self.check_genesis_path(),
            'wallet_name': 'SeedResolve',
            'wallet_seed': seed
        }
        async with Agent(cfg, _BaseAgent, 'Util') as agent:
            agent_did = agent.did
        return agent_did


class Agent:
    def __init__(self, config, instance_cls, issuer_type):
        wallet_seed = config.get('wallet_seed')
        if not wallet_seed:
            raise ValueError('Missing wallet_seed')
        if len(wallet_seed) != 32:
            raise ValueError('wallet_seed length is not 32 characters: {}'.format(wallet_seed))
        genesis_path = config.get('genesis_path')
        if not genesis_path:
            raise ValueError('Missing genesis_path')
        wallet_name = config.get('wallet_name', config.get('id'))
        if not wallet_name:
            raise ValueError('Missing wallet_name')

        self._pool = NodePool(
            wallet_name + '-' + issuer_type,
            genesis_path)

        self._instance_cls = instance_cls
        self._instance = None
        self._wallet = Wallet(
            self._pool,
            wallet_seed,
            wallet_name + '-' + issuer_type + '-Wallet')
        self._opened = None
        self._keep_open = False

    def keep_open(self):
        self._keep_open = True

    async def open(self):
        if self._opened:
            return self._opened
        await self._pool.open()
        self._instance = self._instance_cls(
            await self._wallet.create())
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
