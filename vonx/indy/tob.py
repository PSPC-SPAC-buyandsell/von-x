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
Connection handling specific to using TheOrgBook as a holder/prover
"""

import logging

from .connection import HttpConnection, HttpSession
from .errors import IndyConfigError, IndyConnectionError

LOGGER = logging.getLogger(__name__)

CRED_TYPE_PARAMETERS = (
    "cardinality_fields",
    "credential",
    "description",
    "issuer_url",
    "mapping",
    "topic",
)

def assemble_issuer_spec(config: dict) -> dict:
    """
    Create the issuer JSON definition which will be submitted to TheOrgBook
    """
    issuer_spec = {}
    issuer_email = config.get("email")
    if not issuer_email:
        raise IndyConfigError("Missing issuer email address")
    issuer_did = config.get("did")
    if not issuer_did:
        raise IndyConfigError("Missing issuer DID")

    issuer_spec["issuer"] = {
        "did": issuer_did,
        "name": config.get("name") or "",
        "abbreviation": config.get("abbreviation") or "",
        "email": issuer_email,
        "url": config.get("url") or "",
    }

    if not issuer_spec["issuer"]["name"]:
        raise IndyConfigError("Missing issuer name")

    cred_type_specs = config.get("credential_types")
    if not cred_type_specs:
        raise IndyConfigError("Missing credential_types")
    ctypes = []
    for type_spec in cred_type_specs:
        schema = type_spec["schema"]
        if not type_spec.get("topic"):
            raise IndyConfigError("Missing 'topic' for credential type")
        ctype = {
            "name": type_spec.get("description") or schema.name,
            "endpoint": type_spec.get("issuer_url") or issuer_spec["issuer"]["url"],
            "schema": schema.name,
            "version": schema.version,
            "topic": type_spec["topic"],
        }
        for k in CRED_TYPE_PARAMETERS:
            if k in type_spec and k not in ctype:
                ctype[k] = type_spec[k]
        ctypes.append(ctype)
    issuer_spec["credential_types"] = ctypes
    return issuer_spec


class TobConnection(HttpConnection):
    """
    A class for managing communication with TheOrgBook API and performing the initial
    synchronization as an issuer
    """

    async def sync(self) -> None:
        """
        Submit the issuer JSON definition to TheOrgBook to register our service
        """
        if self.agent_type == "issuer":
            spec = assemble_issuer_spec(self.agent_params)
            response = await self.post_json(
                "indy/register-issuer", spec
            )
            result = response.get("result")
            if not response.get("success"):
                raise IndyConnectionError(
                    "Issuer service was not registered: {}".format(result),
                    400,
                    response,
                )

    @property
    def path_prefix(self):
        return "indy/"

    async def fetch_list(self, path: str) -> dict:
        """
        A standard request to a `list`-style API method

        Args:
            path: The relative path to the API method
        """
        url = self.get_api_url(path)
        LOGGER.debug("fetch_list: %s", url)
        async with HttpSession("fetch_list", self._http_client) as handler:
            response = await handler.client.get(url)
            await handler.check_status(response)
            return await response.json()
