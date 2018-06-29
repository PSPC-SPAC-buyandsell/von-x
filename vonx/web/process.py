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

"""
Handle processing of issue-credential forms
"""

import logging

from aiohttp import web

from . import helpers
from ..indy.errors import IndyClientError

LOGGER = logging.getLogger(__name__)


def load_cred_request(form, attr_names, request: web.Request) -> dict:
    """
    Create a new credential request from a `issue-credential` form definition, fetching
    input from the client request as necessary
    """

    cred = {}
    mapping = form.get("mapping") or {}
    if mapping.get("fill_defaults", True):
        for attr in attr_names:
            cred[attr] = request.get(attr)
            LOGGER.debug("credential %s %s", attr, cred[attr])
    map_attr = mapping.get("attributes") or []
    # Build credential data from schema mapping
    for attribute in map_attr:
        attr_name = attribute.get("name")
        from_type = attribute.get("from", "request")
        # Handle getting value from request data
        if from_type == "request":
            source = attribute.get("source", attr_name)
            cred[attr_name] = request.get(source)
        # Handle getting value from helpers (function defined in config)
        elif from_type == "helper":
            helper = getattr(helpers, attribute["source"], None)
            if not helper:
                raise ValueError("Cannot find helper '{}'".format(attribute["source"]))
            cred[attribute["name"]] = helper()
        # Handle setting value with string literal or None
        elif from_type == "literal":
            cred[attr_name] = attribute.get("source")
        # Handle getting value already set on schema skeleton
        elif from_type == "previous":
            source = attribute.get("source")
            if source:
                try:
                    cred[attr_name] = cred[source]
                except KeyError:
                    raise ValueError(
                        "Cannot find previous value '{}'".format(source))
        else:
            raise ValueError("Unknown mapping type '{}'".format(attribute["from"]))
    return cred


async def process_form(form, request: web.Request) -> web.Response:
    """
    Handle `issue-credential` form processing by looking up the issuer for the schema
    and issuing the credential
    """

    #pylint: disable=broad-except
    if form["type"] == "issue-credential":
        schema_name = form.get("schema_name")
        schema_version = form.get("schema_version")
        if not schema_name:
            # FIXME should be an internal error
            return web.Response(reason="Form definition missing 'schema_name'", status=400)

        LOGGER.debug("request %s", request)
        inputs = await request.json()
        if isinstance(inputs, dict):
            inputs = inputs.get("attributes") or {}
        else:
            inputs = await request.post()

        client = request.app["manager"].get_client()
        try:
            result = await client.resolve_schema(schema_name, schema_version)
        except IndyClientError:
            msg = "Issuer for schema '{}' is not defined or not loaded".format(schema_name)
            return web.Response(reason=msg, status=400)

        params = load_cred_request(form, result.attr_names, inputs)
        #return web.json_response(params)

        try:
            stored = await client.issue_credential(
                result.issuer_id, result.schema_name, result.schema_version,
                result.origin_did, params)
        except IndyClientError as e:
            ret = {"success": False, "result": str(e)}
        else:
            ret = {"success": True, "result": stored.cred_id}

        #if ret["success"]:
        #    return response.html('<h3>Registration successful</h3>')
        #else:
        #    return response.html('<h3>Registration could not be completed</h3>')
        return web.json_response(ret)
    return web.Response(reason="Method not supported", status=405)
