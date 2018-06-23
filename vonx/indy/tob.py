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

import logging

import aiohttp

from .connection import ConnectionBase
from .errors import IndyConfigError, IndyConnectionError
from .messages import (
    CredentialOffer,
    Credential,
    CredentialRequest,
    StoredCredential,
    ProofRequest,
    ConstructedProof,
)

LOGGER = logging.getLogger(__name__)


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
        if not type_spec.get("source_claim"):
            raise IndyConfigError("Missing 'source_claim' for credential type")
        ctype = {
            "name": type_spec.get("description") or schema.name,
            "endpoint": type_spec.get("issuer_url") or issuer_spec["issuer"]["url"],
            "schema": schema.name,
            "version": schema.version,
            "source_claim": type_spec["source_claim"],
        }
        mapping = type_spec.get("mapping")
        if mapping:
            ctype["mapping"] = mapping

        ctypes.append(ctype)
    issuer_spec["credential_types"] = ctypes
    return issuer_spec


async def _handle_request_error(method: str, response=None):
    """
    Handle an exception or bad response from an HTTP request
    """
    if isinstance(response, Exception):
        code = getattr(response, 'code', None)
        raise IndyConnectionError(
            code,
            "Exception during {}: ({}) {}".format(
                method, code, str(response)
            ),
        )
    if response and response.status != 200 and response.status != 201:
        raise IndyConnectionError(
            response.status,
            "Bad response from {}: ({}) {}".format(
                method, response.status, await response.text()
            ),
            response,
        )


class TobConnection(ConnectionBase):
    """
    A class for managing communication with TheOrgBook API and performing the initial
    synchronization as an issuer
    """

    def __init__(self, agent_id: str, agent_params: dict, conn_params: dict):
        super(TobConnection, self).__init__(agent_id, agent_params, conn_params)
        self._agent_params = agent_params
        self._api_url = conn_params.get('api_url')
        if not self._api_url:
            raise IndyConfigError("Missing 'api_url' for TheOrgBook connection")
        self._http_client = None

    @property
    def http_client(self):
        if not self._http_client:
            return aiohttp.ClientSession()
        return self._http_client

    @http_client.setter
    def http_client(self, client):
        self._http_client = client

    async def open(self, service: 'IndyService') -> None:
        # TODO check DID is registered etc ..
        self._http_client = service._agent_http_client(self.agent_id)

    async def sync(self) -> None:
        """
        Submit the issuer JSON definition to TheOrgBook to register our service
        """
        spec = assemble_issuer_spec(self._agent_params)
        response = await self.post_json(
            "indy/register-issuer", spec
        )
        result = response.get("result")
        if not response.get("success"):
            raise IndyConnectionError(
                400,
                "Issuer service was not registered: {}".format(result),
                response,
            )

    async def generate_credential_request(
            self, indy_offer: CredentialOffer) -> CredentialRequest:
        """
        Ask the API to generate a credential request from our credential offer

        Args:
            indy_offer: the result of preparing a credential offer
        """
        response = await self.post_json(
            "indy/generate-credential-request", {
                "credential_offer": indy_offer.offer,
                "credential_definition": indy_offer.cred_def,
            }
        )
        LOGGER.debug("Credential request response: %s", response)
        result = response.get("result")
        if not response.get("success"):
            raise IndyConnectionError(
                400,
                "Could not create credential request: {}".format(result),
                response,
            )
        return CredentialRequest(
            indy_offer,
            result["credential_request"],
            result["credential_request_metadata"])

    async def store_credential(
            self, indy_cred: Credential) -> StoredCredential:
        """
        Ask the API to store a credential

        Args:
            indy_cred: the result of preparing a credential from a credential request
        """
        response = await self.post_json(
            "indy/store-credential", {
                "credential_type": indy_cred.schema_name,
                "credential_data": indy_cred.cred_data,
                "issuer_did": indy_cred.issuer_did,
                "credential_definition": indy_cred.cred_def,
                "credential_request_metadata": indy_cred.cred_req_metadata,
            }
        )
        LOGGER.debug("Store credential response: %s", response)
        result = response.get("result")
        if not response.get("success"):
            raise IndyConnectionError(
                400,
                "Credential was not stored: {}".format(result),
                response,
            )
        return StoredCredential(
            None,
            indy_cred,
            result)

    async def construct_proof(self, request: ProofRequest,
                              params: dict = None) -> ConstructedProof:
        """
        Ask the API to construct a proof from a proof request

        Args:
            proof_request: the prepared Indy proof request
        """
        return await self.post_json(
            "indy/construct-proof", {
                'source_id': params and params.get('source_id') or None,
                'proof_request': request.request,
            }
        )

    def get_api_url(self, path: str = None) -> str:
        """
        Construct the URL for an API request

        Args:
            path: an optional path to be appended to the URL
        """
        url = self._api_url
        if not url.endswith("/"):
            url += "/"
        if path:
            url = url + path
        return url

    async def fetch_list(self, path: str) -> dict:
        """
        A standard request to a `list`-style API method

        Args:
            path: The relative path to the API method
        """
        url = self.get_api_url(path)
        LOGGER.debug("fetch_list: %s", url)
        try:
            response = await self.http_client.get(url)
        except aiohttp.ClientError as e:
            response = e
        await _handle_request_error('fetch_list', response)
        return await response.json()

    async def post_json(self, path: str, data):
        """
        A standard POST request to an API method

        Args:
            path: The relative path to the API method
            data: The body of the request, to be converted to JSON

        Returns:
            the decoded JSON response
        """
        url = self.get_api_url(path)
        LOGGER.debug("post_json: %s", url)
        try:
            response = await self.http_client.post(url, json=data)
        except aiohttp.ClientError as e:
            response = e
        await _handle_request_error('post_json', response)
        return await response.json()
