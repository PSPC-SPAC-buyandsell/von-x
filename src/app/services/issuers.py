from app.services import eventloop
from app.services.requests import Request, RequestResponse
from app.services.tob import TobClient
from app.services.von import VonClient

from von_agent.schema import schema_key_for
from von_agent.util import encode
import json
import logging
logger = logging.getLogger(__name__)


def claim_value_pair(plain):
    return [str(plain), encode(plain)]

def encode_claim(claim):
    encoded_claim = {}
    for key, value in claim.items():
        encoded_claim[key] = claim_value_pair(value) if value else \
            claim_value_pair("")
    return encoded_claim

class IssuerRequest(Request):
    pass

class IssuerResponse(RequestResponse):
    pass

class SubmitClaimRequest(IssuerRequest):
    def __init__(self, schema_name, attribs, schema_version=None, issuer_id=None):
        super(SubmitClaimRequest, self).__init__()
        self.schema_name = schema_name
        self.schema_version = schema_version
        self.attribs = attribs
        self.issuer_id = issuer_id


class IssuerService:
    def __init__(self, spec=None, status_hook=None):
        self.id = None
        self._config = {}
        self._status = {}
        self._status_hook = status_hook
        self._orgbook_did = None
        self._update_config(spec)
        self._update_status({
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
            self.id = self._config['id']
        if 'did' in self._config:
            self._status['did'] = self._config['did']
        if 'api_did' in self._config:
            self._orgbook_did = self._config['api_did']

    def _update_status(self, update=None):
        if update:
            self._status.update(update)
        if self._status_hook:
            self._status_hook(self.id, self._status)

    def ready(self):
        return self._status['ready']

    # Sync with issuer VON client, then TOB client
    async def sync(self):
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
                tob_client = self.init_tob_client()
                await tob_client.sync()
                self._update_status({
                    'orgbook': tob_client.synced
                })
            if self._status['ledger'] and self._status['orgbook']:
                self._update_status({'ready': True, 'syncing': False})
            return self._status['ready']
        except Exception as e:
            logger.exception('Exception during issuer sync process:')
            self._update_status({'ready': False, 'syncing': False})
            #raise e

    def init_von_client(self):
        cfg = self._config.copy()
        return VonClient(cfg)

    def init_tob_client(self, spec=None):
        cfg = self._config.copy()
        cfg['did'] = self._status['did']
        return TobClient(cfg)

    def find_claim_type_for_schema(self, schema_name, schema_version=None):
        ctypes = self._config.get('claim_types')
        if ctypes:
            for ctype in ctypes:
                if 'schema' in ctype and ctype['schema']['name'] == schema_name \
                        and not schema_version or ctype['schema']['version'] == schema_version:
                    return ctype

    def supports_request(self, request : IssuerRequest):
        schema_name = None
        if isinstance(request, SubmitClaimRequest):
            schema_name = request.schema_name
        if schema_name and self.find_claim_type_for_schema(schema_name):
            return True

    def handle_request(self, request : IssuerRequest):
        try:
            if not self.ready():
                raise RuntimeError('Issuer not ready')
            if isinstance(request, SubmitClaimRequest):
                try:
                    result = eventloop.run_coro(
                        self.submit_claim(
                            request.schema_name,
                            request.attribs,
                            schema_version=request.schema_version))
                    return IssuerResponse(request.ident, result)
                except Exception as e:
                    return IssuerResponse(request.ident, None, e)
            else:
                raise ValueError('Unrecognized request type')
        except Exception as e:
            return IssuerResponse(request.ident, None, e)

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

    async def _create_issuer_claim_def(self, issuer, schema_def):
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

    async def submit_claim(self, schema_name, attribs, schema_version=None):
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

        claim = self.load_claim_request(claim_type, attribs)
        encoded_claim = encode_claim(claim)
        self.__log_json('Claim:', encoded_claim)

        von_client = self.init_von_client()
        tob_client = self.init_tob_client()

        async with von_client.create_issuer() as von_issuer:
            (ledger_schema, claim_def_json) = await self._create_issuer_claim_def(
                von_issuer, claim_type['schema'])

            # We create a claim offer
            schema_json = json.dumps(ledger_schema)
            logger.info('Creating claim offer for TOB at DID {}'.format(self._orgbook_did))
            claim_offer_json = await von_issuer.create_claim_offer(schema_json, self._orgbook_did)
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

            (_, claim_json) = await von_issuer.create_claim(
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


