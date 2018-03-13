import json
import logging
import pathlib
import requests
import uuid
from von_agent.agents import \
    _BaseAgent, \
    Issuer as VonIssuer, \
    Verifier as VonVerifier, \
    HolderProver as VonHolderProver
from von_agent.nodepool import NodePool
from von_agent.schema import schema_key_for
from von_agent.wallet import Wallet
logger = logging.getLogger(__name__)


class VonClient:
    def __init__(self, config=None):
        self.config = {'id': None}
        self.issuer_did = None
        self.synced = False
        if config:
            self.config.update(config)

    # Find our DID, and initialize our schemas and claim defs on the ledger
    async def sync(self):
        claims = self.config.get('claim_types')
        if not claims:
            raise ValueError("Missing issuer claims")

        logger.info('Init VON client {} with seed {}'.format(self.config['id'], self.config.get('wallet_seed')))
        async with self.create_issuer() as issuer:
            self.issuer_did = issuer.did
            logger.info('{} issuer DID: {}'.format(self.config['id'], self.issuer_did))
            for claim in claims:
                await self.publish_schema(issuer, claim['schema'])
        self.synced = True
        logger.info('VON client synced: {}'.format(self.config['id']))

    # Make sure that the genesis path is defined, and download the transaction file if needed
    def check_genesis_path(self):
        path = self.config.get('genesis_path')
        if not path:
            raise ValueError("Missing genesis_path")
        genesis_path = pathlib.Path(path)
        if not genesis_path.exists():
            ledger_url = self.config.get('ledger_url')
            if not ledger_url:
                raise ValueError("Cannot retrieve genesis transaction without ledger_url")
            if not genesis_path.parent.exists():
              genesis_path.parent.mkdir(parents = True)

            # download genesis transaction file
            logger.info('Fetching genesis transaction file from {}/genesis'.format(ledger_url))
            response = requests.get('{}/genesis'.format(ledger_url), timeout=10)
            if response.status_code != 200:
                raise RuntimeError('Error downloading genesis file: status {}'.format(response.status))
            data = response.text

            # check data is valid json
            logger.debug('Genesis transaction response: {}'.format(data))
            lines = data.splitlines()
            if not len(lines) or not json.loads(lines[0]):
                raise RuntimeError('Genesis transaction file is not valid JSON')

            # write result to provided path
            with genesis_path.open('x') as output_file:
                output_file.write(data)
            path = str(genesis_path)
            self.config['genesis_path'] = path
        elif genesis_path.is_dir():
            raise ValueError("genesis_path must not point to a directory")
        return path

    async def publish_schema(self, issuer, schema):
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
            self.__log_json('Schema found on ledger:', ledger_schema)
        else:
            schema_json = await issuer.send_schema(json.dumps(schema))
            ledger_schema = json.loads(schema_json)
            if not ledger_schema or not ledger_schema.get('seqNo'):
                raise RuntimeError('Schema was not published to ledger, check DID is registered')
            self.__log_json('Published schema:', ledger_schema)

        # Check if claim definition has been published
        claim_def_json = await issuer.get_claim_def(
            ledger_schema['seqNo'], issuer.did)
        claim_def = json.loads(claim_def_json)

        # If claim definition is not found then publish it
        if claim_def:
            self.__log_json('Claim def found on ledger:', claim_def)
        else:
            claim_def_json = await issuer.send_claim_def(schema_json)
            claim_def = json.loads(claim_def_json)
            self.__log_json('Published claim def:', claim_def)
        return (ledger_schema, claim_def)

    def create_issuer(self):
        # retrieve genesis transaction if necessary
        self.check_genesis_path()
        return Agent(self.config, VonIssuer, 'Issuer')

    async def resolve_did_from_seed(self, seed):
        cfg = {
            'genesis_path': self.check_genesis_path(),
            'wallet_name': 'SeedResolve',
            'wallet_seed': seed
        }
        async with Agent(cfg, _BaseAgent, 'Util') as agent:
            agent_did = agent.did
        return agent_did

    def __log_json(self, heading, data):
        logger.debug(
            "\n============================================================================\n" +
            "{0}\n".format(heading) +
            "{0}\n".format(json.dumps(data, indent=2)) +
            "============================================================================\n")


class Agent:
    def __init__(self, config, instance_cls, issuer_type):
        self.issuer_type = issuer_type
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

        self.pool = NodePool(
            wallet_name + '-' + issuer_type,
            genesis_path)

        self.instance = instance_cls(
            self.pool,
            Wallet(
                self.pool.name,
                wallet_seed,
                wallet_name + '-' + issuer_type + '-Wallet',
            )
        )

    async def __aenter__(self):
        await self.pool.open()
        ret = await self.instance.open()
        if isinstance(self.instance, VonHolderProver):
            # seems odd
            await self.instance.create_master_secret(str(uuid.uuid4()))
        return ret

    async def __aexit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            logger.exception('Exception in VON {}:'.format(self.issuer_type))

        await self.instance.close()
        await self.pool.close()

