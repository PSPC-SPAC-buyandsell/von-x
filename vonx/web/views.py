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
#pylint: disable=broad-except

"""
View classes for handling AJAX requests as an issuer or holder service
"""

from concurrent.futures import Future
import json
import logging

from aiohttp import web

from ..common.exchange import RequestTarget
from ..indy.client import IndyClient, IndyClientError
from ..indy.manager import IndyManager

LOGGER = logging.getLogger(__name__)


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

def indy_client(request: web.Request) -> IndyClient:
    """
    Create an Indy client to perform requests against the ledger service
    """
    return get_manager(request).get_client()


async def health(request: web.Request) -> web.Response:
    """
    Respond with HTTP code 200 if services are ready to accept new credentials, 451 otherwise
    """
    result = await get_manager(request).get_service_status('manager')
    return web.Response(
        text='ok' if result else '',
        status=200 if result else 451)


async def status(request: web.Request) -> web.Response:
    """
    Respond with the current status of the application in JSON format
    """
    result = await get_manager(request).get_service_status('manager')
    return web.json_response(result)


async def ledger_status(request: web.Request) -> web.Response:
    """
    Respond with the status JSON retrieved from the Indy ledger (von-network)
    """
    #pylint: disable=broad-except
    result = await indy_client(request).get_ledger_status()
    try:
        jresult = json.loads(result)
        return web.json_response(jresult)
    except Exception:
        return web.Response(text=result)


async def hello(request: web.Request) -> web.Response:
    """
    Send a test request to the `HelloProcessor` service and return the response
    """
    result = await service_request(request, 'hello', 'isthereanybodyoutthere')
    return web.json_response(result)


def get_handle_id(request: web.Request, handle: str, override_val: str = None) -> str:
    """
    Check the request for a handle ID (connection or holder ID depending on the request)
    which may be overridden depending on the path
    """
    query_val = request.query.get(handle)
    match_val = override_val or request.match_info.get(handle)
    if query_val:
        if match_val and match_val != query_val:
            raise ValueError("{} must be unspecified or equal to '{}'".format(handle, match_val))
    else:
        if not match_val:
            raise ValueError("{} must be specified".format(handle))
        query_val = match_val
    return query_val


async def issue_credential(request: web.Request, connection_id: str = None) -> web.Response:
    """
    Ask the Indy service to issue a credential to the Connection
    """
    try:
        connection_id = get_handle_id(request, 'connection_id', connection_id)
    except ValueError as e:
        return web.Response(text=str(e), status=400)
    schema_name = request.query.get("schema")
    schema_version = request.query.get("version") or None
    if not schema_name:
        return web.Response(text="Missing 'schema' parameter", status=400)
    params = await request.json()
    if not isinstance(params, dict):
        return web.Response(
            text="Request body must contain the schema attributes as a JSON object",
            status=400)
    try:
        stored = await indy_client(request).issue_credential(
            connection_id, schema_name, schema_version, None, params)
        ret = {"success": True, "result": stored.cred_id}
    except IndyClientError as e:
        ret = {"success": False, "result": str(e)}
    return web.json_response(ret)


async def request_proof(request: web.Request, connection_id: str = None) -> web.Response:
    """
    Ask the Indy service to fetch a proof from the Connection
    """
    try:
        connection_id = get_handle_id(request, 'connection_id', connection_id)
    except ValueError as e:
        return web.Response(text=str(e), status=400)
    proof_name = request.query.get('name')
    if not proof_name:
        return web.Response(text="Missing 'name' parameter", status=400)
    inputs = await request.json()
    params = {}
    if isinstance(inputs, dict):
        params = inputs.get('params', params)
        if not isinstance(params, dict):
            return web.Response(
                text="Parameter 'params' must be an object",
                status=400)
    try:
        client = indy_client(request)
        proof_req = await client.generate_proof_request(proof_name)
        verified = await client.request_proof(connection_id, proof_req, None, params)
        result = {
            "verified": verified.verified,
            "parsed_proof": verified.parsed_proof,
            "proof": verified.proof.proof,
        }
        ret = {"success": True, "result": result}
    except IndyClientError as e:
        ret = {"success": False, "result": str(e)}
    return web.json_response(ret)
