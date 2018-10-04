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

import json
import logging

from aiohttp import web

from ..common.util import log_json, normalize_credential_ids
from ..indy.client import IndyClientError

from .view_helpers import (
    IndyRequestError,
    get_handle_id,
    get_manager,
    get_request_json,
    indy_client,
    perform_issue_credential,
    perform_store_credential,
    service_request,
)

LOGGER = logging.getLogger(__name__)


async def health(request: web.Request) -> web.Response:
    """
    Respond with HTTP code 200 if services are ready to accept new credentials, 451 otherwise
    """
    result = await get_manager(request).get_service_status('manager')
    ok = result and result.get("services", {}).get("indy", {}).get("synced")
    return web.Response(
        text='ok' if ok else '',
        status=200 if ok else 451)


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


async def issue_credential(request: web.Request, connection_id: str = None) -> web.Response:
    """
    Ask the Indy service to issue a credential to the Connection
    """
    try:
        connection_id = get_handle_id(request, "connection_id", connection_id)
        client = indy_client(request)
        params = await get_request_json(request)
        schema_name = request.query.get("schema")
        schema_version = request.query.get("version")
        stored, ret = await perform_issue_credential(
            client, connection_id, params, schema_name, schema_version)
    except IndyRequestError as e:
        return e.response

    response = web.json_response(ret)
    response["stored"] = stored
    return response


async def request_proof(request: web.Request, connection_id: str = None) -> web.Response:
    """
    Ask the Indy service to fetch a proof from the Connection
    """
    try:
        connection_id = get_handle_id(request, "connection_id", connection_id)
        inputs = await get_request_json(request)
        proof_name = request.query.get("name")
        if not proof_name:
            raise IndyRequestError("Missing 'name' parameter")
        params = {}
        cred_ids = request.query.get("credential_ids", request.query.get("credential_id"))
        if isinstance(inputs, dict):
            params = inputs.get("params", params)
            if not isinstance(params, dict):
                raise IndyRequestError("Parameter 'params' must be an object")
            cred_ids = normalize_credential_ids(inputs.get("credential_ids", cred_ids))
    except IndyRequestError as e:
        return e.response

    try:
        client = indy_client(request)
        proof_req = await client.generate_proof_request(proof_name)
        verified = await client.request_proof(connection_id, proof_req, cred_ids, params)
        result = {
            "verified": verified.verified,
            "parsed_proof": verified.parsed_proof,
            "proof": verified.proof.proof,
        }
        ret = {"success": True, "result": result}
    except IndyClientError as e:
        ret = {"success": False, "result": str(e)}
    return web.json_response(ret)


async def generate_credential_request(request, holder_id: str = None):
    """
    Processes a credential definition and responds with a credential request
    which can then be used to submit a credential.

    Example request payload:
    ```json
    {
        'credential_offer': <credential offer json>,
        'credential_definition_id': <credential definition id>
    }
    ```

    Returns:
    ```
    {
        "credential_request": <credential request json>,
        "credential_request_metadata": <credential request metadata json>
    }
    ```
    """

    try:
        holder_id = get_handle_id(request, "holder_id", holder_id)
        params = await get_request_json(request)
        offer = params.get("credential_offer")
        if not offer:
            raise IndyRequestError("Missing 'credential_offer'")
        cred_def = params.get("credential_definition")
        if cred_def:
            cred_def_id = cred_def.get("id")
        else:
            cred_def_id = params.get("credential_definition_id")
        if not cred_def_id:
            raise IndyRequestError("Missing 'credential_definition_id'")
    except IndyRequestError as e:
        return e.response

    try:
        cred_request = await indy_client(request).create_credential_request(
            holder_id, offer, cred_def_id)
        ret = {
            "success": True,
            "result": {
                "credential_request": cred_request.data,
                "credential_request_metadata": cred_request.metadata,
            }}
    except IndyClientError as e:
        cred_request = None
        ret = {"success": False, "result": str(e)}
    response = web.json_response(ret)
    response["cred_request"] = cred_request
    return response


async def store_credential(request, holder_id: str = None):
    """
    Stores a verifiable credential in wallet.
    The data in the credential is parsed and stored in the database
    for search/display purposes based on the issuer's processor config.
    The data is then made available through a REST API as well as a
    search API.

    Example request payload:
    ```json
    {
        "credential_data": <credential data>,
        "credential_request_metadata": <credential request metadata>
    }
    ```

    Returns: created verified credential model
    """
    try:
        holder_id = get_handle_id(request, "holder_id", holder_id)
        client = indy_client(request)
        params = await get_request_json(request)
        stored, ret = await perform_store_credential(client, holder_id, params)
    except IndyRequestError as e:
        return e.response

    response = web.json_response(ret)
    response["stored"] = stored
    return response


async def construct_proof(request, holder_id: str = None):
    """
    Constructs a proof given a proof request and source_id
   ```json
    {
        "proof_request": <HL Indy proof request>,
        "source_id": <source if of subject>
    }
    ```

    Returns: HL Indy proof data
    """
    try:
        holder_id = get_handle_id(request, "holder_id", holder_id)
        params = await get_request_json(request)
        proof_request = params.get("proof_request")
        if not proof_request:
            raise IndyRequestError("Missing 'proof_request'")
    except IndyRequestError as e:
        return e.response

    wql_filters = None # params.get("wql_filters")
    cred_ids = normalize_credential_ids(params.get("credential_ids"))
    try:
        LOGGER.debug("Performing proof request with cred IDs: %s", cred_ids)
        proof = await indy_client(request).construct_proof(
            holder_id, proof_request, wql_filters, cred_ids)
        ret = {"success": True, "result": proof.proof}
    except IndyClientError as e:
        proof = None
        ret = {"success": False, "result": str(e)}
    log_json("Proof response:", ret, LOGGER)
    response = web.json_response(ret)
    response["proof"] = proof
    return response
