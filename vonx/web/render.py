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
Handle rendering of issue-credential forms
"""


import logging

from aiohttp import web
import aiohttp_jinja2

from ..common.util import log_json, normalize_credential_ids
from ..indy.errors import IndyClientError

LOGGER = logging.getLogger(__name__)


async def render_form(form: dict, request: web.Request) -> web.Response:
    """
    Render a form definition by:

        - performing a proof request if needed,
        - collecting any values needed from the proof request,
        - adding any user input,
        - populating template variables,
        - and rendering the template defined by the form definition

    Args:
        form: The form definition
        request: The request received by aiohttp
    """
    #pylint: disable=broad-except
    proof_meta = form.get("proof_request")
    proof_response = None
    service_mgr = request.app["manager"]

    if proof_meta:
        try:
            client = service_mgr.get_client()
            proof_req = await client.generate_proof_request(proof_meta["id"])

            params = {}
            if "params" in proof_meta:
                for attr_name, param in proof_meta["params"].items():
                    if isinstance(param, str):
                        param_from = param
                    elif isinstance(param, dict):
                        param_from = param.get("from")
                    if param_from:
                        val = request.query.get(param_from)
                        if val is not None and val != '':
                            params[attr_name] = val

            cred_ids = request.query.get("credential_ids", request.query.get("credential_id"))
            cred_ids = normalize_credential_ids(cred_ids)

            verified = await client.request_proof(
                proof_meta["connection_id"], proof_req, cred_ids, params)
            proof_response = {
                "success": True,
                "verified": verified.verified == "true",
                "parsed_proof": verified.parsed_proof,
                "proof": verified.proof.proof,
            }
        except IndyClientError as e:
            proof_response = {"success": False, "result": str(e)}
        log_json("Proof response:", proof_response, LOGGER, logging.INFO)

    tpl_name = form.get("template", "index.html")
    tpl_vars = {
        "inputs": {},
        "request": {},
        "proof_response": proof_response,
        "THE_ORG_BOOK_APP_URL": service_mgr.env.get("TOB_APP_URL")
    }
    tpl_vars["inputs"].update(request.query)
    tpl_vars["request"].update(request.query)
    if proof_response and proof_response["success"]:
        # currently flattening attributes from different schemas
        proof_attrs = {}
        for attrs in proof_response["parsed_proof"].values():
            proof_attrs.update(attrs)

        if "inputs" in proof_req:
            for input_name, claim_name in proof_req["inputs"].items():
                tpl_vars["inputs"][input_name] = proof_attrs.get(claim_name, "")
        else:
            tpl_vars["inputs"].update(proof_attrs)
    tpl_vars.update(form)
    if "hidden" not in tpl_vars:
        tpl_vars["hidden"] = []
    if "connection_id" not in tpl_vars["hidden"]:
        tpl_vars["hidden"].append("connection_id")
    tpl_vars["inputs"]["connection_id"] = form.get("connection_id", "")
    tpl_vars["path"] = request.rel_url

    return aiohttp_jinja2.render_template(tpl_name, request, tpl_vars)
