import asyncio
from collections import OrderedDict
from concurrent.futures import Future
import json
import logging

from aiohttp import web

from ..common.exchange import RequestTarget
from ..indy.client import IndyClient, IndyClientError
from ..indy.errors import IndyError
from ..indy.messages import Credential, StoredCredential
from ..indy.manager import IndyManager

from .headers import KeyFinderBase, verify_signature

LOGGER = logging.getLogger(__name__)


class IndyRequestError(IndyError):
    """
    An exception in parsing request parameters
    """
    def __init__(self, message: str, *, status=400):
        super(IndyRequestError, self).__init__(message)
        self.message = message
        self.status = status

    @property
    def response(self):
        return web.Response(text=self.message, status=self.status)

class IndyCredentialProcessorException(IndyRequestError):
    """
    Base exception for :class:`IndyCredentialProcessor`
    """
    pass

class IndyCredentialProcessor:
    """
    Base class for post-storage credential processing operations
    """
    def __init__(self):
        pass

    def start_batch(self) -> object:
        """
        May return batch info used for caching and/or scheduling
        """
        pass

    def process_credential(
            self, _stored: StoredCredential, _origin_did: str = None, _batch_info=None) -> Future:
        """
        Perform post-processing (DB indexing, etc)
        """
        return None

    async def process_credential_async(
            self, stored: StoredCredential, origin_did: str = None,
            batch_info=None) -> asyncio.Future:
        fut = self.process_credential(stored, origin_did, batch_info)
        if fut:
            return await asyncio.wrap_future(fut)

    def end_batch(self, batch_info):
        """
        Ensure that processing has been kicked off
        """
        pass


def get_manager(request: web.Request) -> IndyManager:
    """
    Fetch the service manager for the current application
    """
    return request.app['manager']

def get_request_target(request: web.Request, service_name: str) -> RequestTarget:
    """
    Create a :class:`RequestTarget` to process requests to a specific service

    Args:
        request: the incoming HTTP request
        service_name: the name of the service registered with the service manager
    """
    return get_manager(request).get_service_request_target(service_name)

def service_request(request: web.Request, service_name: str, message) -> Future:
    """
    Handle a single request to a running service and await the result in a thread

    Args:
        request: the incoming HTTP request
        service_name: the name of the service registered with the service manager
        message: the body of the message to be sent
    """
    return get_request_target(request, service_name).request(message)

async def get_request_json(request):
    try:
        return await request.json()
    except json.JSONDecodeError:
        raise IndyRequestError(
            "Request body must contain an application/json payload")

def indy_client(request: web.Request) -> IndyClient:
    """
    Create an Indy client to perform requests against the ledger service
    """
    return get_manager(request).get_client()

def get_handle_id(request: web.Request, handle: str, override_val: str = None) -> str:
    """
    Check the request for a handle ID (connection or holder ID depending on the request)
    which may be overridden depending on the path
    """
    query_val = request.query.get(handle)
    match_val = override_val or request.match_info.get(handle)
    if query_val:
        if match_val and match_val != query_val:
            raise IndyRequestError(
                "{} must be unspecified or equal to '{}'".format(handle, match_val))
    else:
        if not match_val:
            raise IndyRequestError(
                "{} must be specified".format(handle))
        query_val = match_val
    return query_val

async def check_request_signature(
        request: web.Request, key_finder: KeyFinderBase, required: bool = False):
    """
    Check the DID-auth signature on the incoming request
    """
    if request.get("didauth"):
        return True, request["didauth"]
    auth = None
    try:
        auth = await verify_signature(
            request.headers, key_finder, request.method, request.path_qs)
    except IndyError as e:
        LOGGER.exception("Signature validation error:")
        raise IndyRequestError("Signature validation error") from e
    except Exception as e:
        LOGGER.exception("Signature validation error:")
        raise IndyRequestError("Not available", status=503) from e
    request["didauth"] = auth
    if not auth and required:
        raise IndyRequestError("Signature required", status=401)
    return auth

def get_request_did(request):
    auth = request.get("didauth")
    did = auth and auth["keyId"] or None
    if did and did.startswith("did:sov:"):
        did = did[8:]
    return did

def _assemble_cred_from_input(params: dict):
    """
    Assemble a single credential object from input
    """
    data = params.get("credential_data")
    if not data:
        raise IndyRequestError("Missing 'credential_data'")
    metadata = params.get("credential_request_metadata")
    if not metadata:
        raise IndyRequestError("Missing 'credential_request_metadata'")
    revoc_id = params.get("credential_revocation_id")
    return Credential(
        data,
        metadata,
        revoc_id,
    )


async def _issue_credential(
        client: IndyClient, connection_id: str,
        schema_name, schema_version, attribs, batch: bool = False):
    """
    Issue a single credential or batch of credentials
    """
    try:
        if batch:
            batch = await client.issue_credential_batch(
                connection_id, schema_name, schema_version, None, attribs)
            stored = []
            result = []
            erridx = 0
            for stored_cred in batch.results:
                if stored_cred.cred_id:
                    row = {"success": True, "result": stored_cred.cred_id}
                else:
                    errmsg = batch.errors[erridx] \
                        if batch.errors and erridx < len(batch.errors) else None
                    erridx += 1
                    row = {"success": False, "result": errmsg}
                if stored_cred.served_by:
                    row["served_by"] = stored_cred.served_by
                stored.append(stored_cred)
                result.append(row)
        else:
            stored = await client.issue_credential(
                connection_id, schema_name, schema_version, None, attribs)
            result = {"success": True, "result": stored.cred_id}
            if stored.served_by:
                result["served_by"] = stored.served_by
    except IndyClientError as e:
        stored = None
        result = {"success": False, "result": str(e)}
        if batch:
            stored = [stored for _row in attribs]
            result = [result for _row in attribs]
    return stored, result


async def perform_issue_credential(
        client: IndyClient, connection_id: str, params, schema_name=None, schema_version=None):
    """
    Parse request body into credential details and perform issuing
    """
    if isinstance(params, list):
        queue = OrderedDict()
        processed = {}
        orig_pos = []
        for cred in params:
            if not isinstance(cred, dict):
                raise IndyRequestError("Expected JSON object")
            if "schema" not in cred:
                raise IndyRequestError("Missing 'schema' property")
            if not isinstance(cred.get("attributes"), dict):
                raise IndyRequestError("Missing or non-dictionary 'attributes' property")
            key = (cred["schema"], cred.get("version"))
            if key not in queue:
                queue[key] = []
            orig_pos.append( (key, len(queue[key])) )
            queue[key].append(cred["attributes"])
        for key, attribs in queue.items():
            processed[key] = await _issue_credential(
                client, connection_id, key[0], key[1], attribs, True)
        stored = []
        result = []
        for key, pos in orig_pos:
            row = processed[key]
            stored.append(row[0][pos])
            result.append(row[1][pos])
        return stored, result
    else:
        if not schema_name:
            raise IndyRequestError("Missing 'schema' parameter")
        elif not isinstance(params, dict):
            raise IndyRequestError(
                "Request body must contain the credential attributes as a JSON object")
        return await _issue_credential(
            client, connection_id, schema_name, schema_version, params)


async def _store_credential(
        client: IndyClient, holder_id: str, cred: Credential,
        processor: IndyCredentialProcessor = None, origin_did: str = None,
        batch_info=None):
    """
    Process credential storage
    """
    stored = None
    try:
        stored = await client.store_credential(holder_id, cred)
        result = {"success": True, "result": stored.cred_id}
        if processor:
            await processor.process_credential_async(stored, origin_did, batch_info)
    except IndyClientError as e: # includes IndyCredentialProcessorException
        result = {"success": False, "result": str(e)}
    return stored, result


async def perform_store_credential(
        client: IndyClient, holder_id: str, params,
        processor: IndyCredentialProcessor = None, origin_did: str = None):
    """
    Parse request body into credential details and perform storage
    """

    if isinstance(params, list) and params:
        procs = []
        batch_info = processor.start_batch() if processor else None
        for cred in map(_assemble_cred_from_input, params):
            procs.append(asyncio.ensure_future(
                _store_credential(client, holder_id, cred, processor, origin_did, batch_info)))
        if batch_info:
            processor.end_batch(batch_info)
        await asyncio.wait(procs)
        stored = []
        result = []
        for proc in procs:
            stored_row, ret_row = proc.result()
            stored.append(stored_row)
            result.append(ret_row)
    elif isinstance(params, dict):
        cred = _assemble_cred_from_input(params)
        stored, result = await _store_credential(client, holder_id, cred, processor, origin_did)
    else:
        raise IndyRequestError(
            "Request body must contain the request parameters as a JSON object or list")
    return stored, result
