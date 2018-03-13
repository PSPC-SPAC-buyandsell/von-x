from app.services import eventloop
from app.services.issuer import IssuerRequest, IssuerResponse, IssuerService
from app.services.request import Request, RequestExecutor, RequestProcessor, StatusResponse
from app.services.von import VonClient

from concurrent.futures import ThreadPoolExecutor
import logging
logger = logging.getLogger(__name__)


def init_claim_request_processor(app):
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
            logger.info("Initializing processor for services: {}".format(', '.join(issuer_ids)))
            return ClaimRequestProcessor(app.config, issuers)
        else:
            raise ValueError("No defined issuers referenced by ISSUERS")
    else:
        raise ValueError("No issuers defined by config")

def init_claim_request_executor(processor):
    return RequestExecutor(processor)


class ClaimRequestProcessor(RequestProcessor):
    def __init__(self, config, issuer_specs):
        super(ClaimRequestProcessor, self).__init__()
        self._config = config or {}
        self._executor = ThreadPoolExecutor(max_workers=5)
        self._issuers = {}
        self._issuer_specs = issuer_specs
        self._issuer_status = {}
        self._orgbook_did = None
        self._ready = False

    def ready(self):
        return self._ready

    def status(self):
        return {
            'issuers': self._issuer_status.copy(),
            'orgbook_did': self._orgbook_did,
            'ready': self._ready,
            'version': self._config.get('VERSION')
        }

    def _run_services(self):
        async def resolve():
            try:
                await self.resolve_orgbook_did()
            except Exception as e:
                raise RuntimeError('Error while resolving DID for TOB') from e
            self.start_issuers()
        eventloop.run_in_thread(resolve(), self._executor)

    # Resolve DID for orgbook from given seed if necessary
    async def resolve_orgbook_did(self):
        if not self._orgbook_did:
            tob_did = self._config.get('TOB_INDY_DID')
            if not tob_did:
                tob_seed = self._config.get('TOB_INDY_SEED')
                if not tob_seed:
                    raise ValueError('Either TOB_INDY_SEED or TOB_INDY_DID must be defined')
                logger.info('Resolving TOB DID from seed {}'.format(tob_seed))
                # create 'blank' client with no issuer information
                von_client = self.init_von_client()
                tob_did = await von_client.resolve_did_from_seed(tob_seed)
                if not tob_did:
                    raise ValueError('DID for TOB could not be resolved')
                self._orgbook_did = tob_did
                logger.info('Resolved TOB DID to {}'.format(tob_did))
        return self._orgbook_did

    def extend_issuer_spec(self, spec):
        spec = spec.copy() if spec else {}
        if not 'genesis_path' in spec:
            spec['genesis_path'] = self._config.get('INDY_GENESIS_PATH')
        if not 'ledger_url' in spec:
            spec['ledger_url'] = self._config.get('INDY_LEDGER_URL')
        if not 'api_url' in spec:
            spec['api_url'] = self._config.get('TOB_API_URL')
        spec['api_did'] = self._orgbook_did
        return spec

    def init_von_client(self):
        cfg = {
            'genesis_path': self._config.get('INDY_GENESIS_PATH'),
            'ledger_url': self._config.get('INDY_LEDGER_URL')
        }
        return VonClient(cfg)

    def start_issuers(self):
        logger.info('Starting issuers')
        for spec in self._issuer_specs:
            service = IssuerService(self.extend_issuer_spec(spec), self._status_updated)
            self._issuers[service.id] = service
        for id, service in self._issuers.items():
            future = eventloop.run_in_thread(service.sync(), self._executor)

    def find_issuer_for_request(self, request : IssuerRequest):
        for id, service in self._issuers.items():
            if service.supports_request(request):
                return service

    def _handle_request(self, request : Request):
        if not isinstance(request, IssuerRequest):
            return
        service = self.find_issuer_for_request(request)
        if service:
            request.ident['issuer_id'] = service.id
            try:
                response = service.handle_request(request)
            except Exception as e:
                response = IssuerResponse(request.ident, None, e)
            self._send_output(response)
            return True
        # empty response will raise an exception

    def _status_updated(self, id, status):
        self._issuer_status[id] = status
        self.update_status()

    def update_status(self):
        ok = True
        old_ok = self._ready
        for id, handle in self._issuers.items():
            if not self._issuer_status.get(id, {}).get('ready'):
                ok = False
                break
        self._ready = ok
        if ok and not old_ok:
            logger.info('Completed claim handler initialization')
        self._send_output(StatusResponse(self.status()))
