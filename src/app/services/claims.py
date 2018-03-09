import asyncio
import json
import logging
import threading
from .tob import TobClient
from .von import VonClient
from von_agent.schema import schema_key_for
from von_agent.util import encode
logger = logging.getLogger(__name__)


def claim_value_pair(plain):
    return [str(plain), encode(plain)]

def encode_claim(claim):
    encoded_claim = {}
    for key, value in claim.items():
        encoded_claim[key] = claim_value_pair(value) if value else \
            claim_value_pair("")
    return encoded_claim


def init_claim_handler(app):
	if hasattr(app, 'global_config') and 'issuers' in app.global_config:
		issuers = []
		issuer_ids = []
		limit_issuers = app.config.get('ISSUERS', '').strip()
		limit_issuers = limit_issuers.split() \
			if (limit_issuers != '' and limit_issuers != 'all') \
			else None
		for issuer_key, issuer in app.global_config['issuers'].items():
			if not 'id' in issuer:
				issuer['id'] = issuer_key
			if not limit_issuers or issuer['id'] in limit_issuers:
				issuers.append(issuer)
				issuer_ids.append(issuer['id'])
		if len(issuers):
			logger.info("Starting issuer services: {}".format(', '.join(issuer_ids)))
			app.claim_handler = ClaimHandler(app.config, issuers)
			app.claim_handler.init_sync()
		else:
			raise ValueError("No defined issuers referenced by ISSUERS")
	else:
		raise ValueError("No issuers defined by config")


# A class to coordinate operations involving both of the clients
class ClaimHandler:
    def __init__(self, config, issuer_specs):
        self.config = config or {}
        self.issuer_specs = issuer_specs or []
        self.issuer_status = {}
        self.orgbook_did = None
        self.synced = False
        self.sync_loop = None
        self.init_issuer_status()

    def init_issuer_status(self):
        for spec in self.issuer_specs:
            status = {
                'did': None,
                'ledger': False,
                'orgbook': False,
                'ready': False
            }
            self.issuer_status[spec['id']] = status

    def ready(self):
        return self.synced

    def status(self):
        return {
            'issuers': self.issuer_status.copy(),
            'orgbook_did': self.orgbook_did,
            'ready': self.synced,
            'version': self.config.get('VERSION')
        }

    # Perform initialization of issuer services in a separate thread
    def init_sync(self):
        if not self.sync_loop:
            self.sync_loop = asyncio.new_event_loop()
        def start_sync_loop(loop):
            asyncio.set_event_loop(loop)
            loop.run_forever()
        t1 = threading.Thread(target=start_sync_loop, args=(self.sync_loop,))
        t1.start()

        def done_resolve(future):
            if future.exception():
                raise RuntimeError('Error while resolving DID for TOB') from future.exception()
            else:
                self.sync_issuers()
        asyncio.run_coroutine_threadsafe(
            self.resolve_orgbook_did(),
            self.sync_loop
        ).add_done_callback(done_resolve)
        return t1

    # Resolve DID for orgbook from given seed if necessary
    async def resolve_orgbook_did(self):
        if not self.orgbook_did:
            tob_did = self.config.get('TOB_INDY_DID')
            if not tob_did:
                tob_seed = self.config.get('TOB_INDY_SEED')
                if not tob_seed:
                    raise ValueError('Either TOB_INDY_SEED or TOB_INDY_DID must be defined')
                logger.info('Resolving TOB DID from seed {}'.format(tob_seed))
                # create 'blank' client with no issuer information
                von_client = self.init_von_client()
                tob_did = await von_client.resolve_did_from_seed(tob_seed)
                if not tob_did:
                    raise ValueError('DID for TOB could not be resolved')
                self.orgbook_did = tob_did
                logger.info('Resolved TOB DID to {}'.format(tob_did))
        return self.orgbook_did

    # Set up each issuer to sync in the event loop (simultaneously)
    def sync_issuers(self):
        for spec in self.issuer_specs:
            asyncio.run_coroutine_threadsafe(
                self.sync_issuer(spec),
                self.sync_loop
            ).add_done_callback(lambda future: self.done_issuer_sync(future))

    def done_issuer_sync(self, future):
        if future.exception():
            # FIXME - pass issuer ID in here to get more useful logging
            raise RuntimeError('Error while syncing issuer') \
                from future.exception()
        else:
            self.update_status(future.result())

    # Update overall status when an issuer sync has completed
    def update_status(self, result=None):
        ok = True
        old_ok = self.synced
        for spec in self.issuer_specs:
            if not self.issuer_status[spec['id']]['ready']:
                ok = False
                break
        self.synced = ok
        if ok and not old_ok:
            logger.info('Completed claim handler initialization')
            # shut down the event loop & thread if we have nothing more to sync
            self.sync_loop.stop()

    # Sync with issuer VON client, then TOB client
    async def sync_issuer(self, spec):
        status = self.issuer_status[spec['id']]
        von_client = self.init_von_client(spec)
        await von_client.sync()
        status.update({
            'did': von_client.issuer_did,
            'ledger': von_client.synced
        })
        if von_client.synced:
            tob_client = self.init_tob_client(spec)
            await tob_client.sync()
            status.update({
                'orgbook': tob_client.synced
            })
        if status['ledger'] and status['orgbook']:
            status['ready'] = True
        return {'id': spec['id'], 'ready': status['ready']}

    def init_von_client(self, spec=None):
        cfg = spec.copy() if spec else {}
        if not 'genesis_path' in cfg:
            cfg['genesis_path'] = self.config.get('INDY_GENESIS_PATH')
        if not 'ledger_url' in cfg:
            cfg['ledger_url'] = self.config.get('INDY_LEDGER_URL')
        return VonClient(cfg)

    def init_tob_client(self, spec=None):
        cfg = spec.copy() if spec else {}
        if not 'api_url' in cfg:
            cfg['api_url'] = self.config.get('TOB_API_URL')
        if not 'did' in cfg:
            cfg['did'] = self.issuer_status[spec['id']]['did']
        return TobClient(cfg)

    def find_issuer_for_schema(self, schema_name):
        for spec in self.issuer_specs:
            types = spec.get('claim_types')
            if not types:
                continue
            for claim_type in types:
                if 'schema' in claim_type and claim_type['schema']['name'] == schema_name:
                    return (spec, claim_type)

    def load_claim_request(self, claim_type, request):
        # Build schema body skeleton
        claim = {}
        for attr in claim_type['schema']['attr_names']:
            claim[attr] = None

        mapping = claim_type.get('mapping')
        if not mapping:
            # Default to copying schema attributes by name if no mapping is provided
            for attr in claim_type['schema']['attr_names']:
                claim[attr] = request.get(attr)
        else:
            # Build claim data from schema mapping
            for attribute in mapping:
                attr_name = attribute.get('name')
                from_type = attribute.get('from', 'request')
                # Handle getting value from request data
                if from_type == 'request':
                    source = attribute.get('source', attr_name)
                    claim[attr_name] = request.get(source)
                # Handle getting value from helpers (function defined in config)
                elif from_type == 'helper':
                    #try:
                    #    helpers = import_module('von_connector.helpers')
                    #    helper = getattr(helpers, attribute['source'])
                    #    claim[attribute['name']] = helper()
                    #except AttributeError:
                    #    raise Exception(
                    #        'Cannot find helper "%s"' % attribute['source'])
                    pass
                # Handle setting value with string literal or None
                elif from_type == 'literal':
                    claim[attr_name] = attribute.get('source')
                # Handle getting value already set on schema skeleton
                elif from_type == 'previous':
                    source = attribute.get('source')
                    if source:
                        try:
                            claim[attr_name] = claim[source]
                        except KeyError:
                            raise ValueError(
                                'Cannot find previous value "%s"' % source)
                else:
                    raise ValueError('Unkown mapping type "%s"' % attribute['from'])
        return claim

    async def create_issuer_claim_def(self, issuer, schema_def):
        self.__log_json('Schema definition:', schema_def)

        # We need schema from ledger
        schema_json = await issuer.get_schema(
            schema_key_for({
                'origin_did': issuer.did,
                'name': schema_def['name'],
                'version': schema_def['version']
            }))
        ledger_schema = json.loads(schema_json)

        self.__log_json('Schema:', ledger_schema)

        claim_def_json = await issuer.get_claim_def(
            ledger_schema['seqNo'], issuer.did)
        return (ledger_schema, claim_def_json)

    async def submit_claim(self, request):
        if not self.ready():
            raise RuntimeError("Claim handler is not ready")
        if not request:
            # FIXME - raise a validation error to return an appropriate HTTP status
            raise RuntimeError("Missing request data")

        schema_name = request.get('schema')
        if not schema_name:
            raise ValueError('Missing schema value')
        found_issuer = self.find_issuer_for_schema(schema_name)
        if not found_issuer:
            raise ValueError('Issuer not found for schema type "{}"'.format(schema_name))
        issuer_spec, claim_type = found_issuer

        claim = self.load_claim_request(claim_type, request)
        encoded_claim = encode_claim(claim)
        self.__log_json('Claim:', encoded_claim)

        von_client = self.init_von_client(issuer_spec)
        tob_client = self.init_tob_client(issuer_spec)

        async with von_client.create_issuer() as issuer:
            (ledger_schema, claim_def_json) = await self.create_issuer_claim_def(
                issuer, claim_type['schema'])

            # We create a claim offer
            schema_json = json.dumps(ledger_schema)
            logger.info('Creating claim offer for TOB at DID {}'.format(self.orgbook_did))
            claim_offer_json = await issuer.create_claim_offer(schema_json, self.orgbook_did)
            claim_offer = json.loads(claim_offer_json)

            self.__log_json('Requesting claim request:', {
                'claim_offer': claim_offer,
                'claim_def': json.loads(claim_def_json)
            })

            claim_req = tob_client.create_record('bcovrin/generate-claim-request', {
                'claim_offer': claim_offer_json,
                'claim_def': claim_def_json
            })
            self.__log_json('Got claim request:', claim_req)

            claim_request_json = json.dumps(claim_req)

            (_, claim_json) = await issuer.create_claim(
                claim_request_json, encoded_claim)

        self.__log_json('Created claim:', json.loads(claim_json))

        # Store claim
        return tob_client.create_record('bcovrin/store-claim', {
            'claim_type': ledger_schema['data']['name'],
            'claim_data': json.loads(claim_json)
        })

    def __log_json(self, heading, data):
        logger.debug(
            "\n============================================================================\n" +
            "{0}\n".format(heading) +
            "{0}\n".format(json.dumps(data, indent=2)) +
            "============================================================================\n")
