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

from .indy import (
    IndyCredOffer,
    IndyCredential,
    IndyCredentialRequest,
    IndyStoredCredential)

LOGGER = logging.getLogger(__name__)


def assemble_issuer_spec(config: dict) -> dict:
    """
    Create the issuer JSON definition which will be submitted to TheOrgBook
    """
    issuer_spec = {}
    issuer_email = config.get("email")
    if not issuer_email:
        raise ValueError("Missing issuer email address")
    issuer_did = config.get("did")
    if not issuer_did:
        raise ValueError("Missing issuer DID")

    issuer_spec["issuer"] = {
        "did": issuer_did,
        "name": config.get("name", ""),
        "abbreviation": config.get("abbreviation", ""),
        "email": issuer_email,
        "url": config.get("url", ""),
    }

    if not issuer_spec["issuer"]["name"]:
        raise ValueError("Missing issuer name")

    cred_type_specs = config.get("credential_types")
    if not cred_type_specs:
        raise ValueError("Missing credential_types")
    ctypes = []
    for type_spec in cred_type_specs:
        schema = type_spec["schema"]
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
    LOGGER.info('\n\n\n\n-----------')
    LOGGER.info(issuer_spec)
    return issuer_spec


class TobClientError(Exception):
    """
    A generic exception representing an issue with a TobClient operation
    """

    def __init__(self, status_code, message: str, response=None):
        super(TobClientError, self).__init__(message)
        self.status_code = status_code
        self.message = message
        self.response = response


async def _handle_request_error(method: str, response=None):
    """
    Handle an exception or bad response from an HTTP request
    """
    if isinstance(response, Exception):
        code = getattr(response, 'code', None)
        raise TobClientError(
            code,
            "Exception during {}: ({}) {}".format(
                method, code, str(response)
            ),
        )
    if response and response.status != 200 and response.status != 201:
        raise TobClientError(
            response.status,
            "Bad response from {}: ({}) {}".format(
                method, response.status, await response.text()
            ),
            response,
        )


class TobClient:
    """
    A class for managing communication with TheOrgBook API and performing the initial
    synchronization as an issuer
    """

    def __init__(self, http_client, api_url: str):
        self._http_client = http_client
        self._api_url = api_url

    async def register_issuer(self, issuer_cfg: dict):
        """
        Submit the issuer JSON definition to TheOrgBook to register our service

        Args:
            issuer_cfg: the issuer configuration to be converted into JSON format
        """
        spec = assemble_issuer_spec(issuer_cfg)
        response = await self.post_json(
            "indy/register-issuer", spec
        )
        result = response.get("result")
        if not response.get("success"):
            raise TobClientError(
                400,
                "Issuer service was not registered: {}".format(result),
                response,
            )
        return result

    async def generate_credential_request(
            self, indy_offer: IndyCredOffer) -> IndyCredentialRequest:
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
            raise TobClientError(
                400,
                "Could not create credential request: {}".format(result),
                response,
            )
        return IndyCredentialRequest(
            None,
            indy_offer,
            result["credential_request"],
            result["credential_request_metadata"])

    async def store_credential(
            self, indy_cred: IndyCredential) -> IndyStoredCredential:
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
            raise TobClientError(
                400,
                "Credential was not stored: {}".format(result),
                response,
            )
        return IndyStoredCredential(
            None,
            indy_cred,
            result)

    async def construct_proof(self, proof_request: dict):
        """
        Ask the API to construct a proof from a proof request

        Args:
            proof_request: the prepared Indy proof request
        """
        return await self.post_json(
            "indy/construct-proof", proof_request
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
            http_client: The :class:`ClientSession` instance responsible for adding
                authentication headers
            path: The relative path to the API method
        """
        url = self.get_api_url(path)
        LOGGER.debug("fetch_list: %s", url)
        try:
            response = await self._http_client.get(url)
        except aiohttp.ClientError as e:
            response = e
        await _handle_request_error('fetch_list', response)
        return await response.json()

    async def post_json(self, path: str, data):
        """
        A standard POST request to an API method

        Args:
            http_client: The :class:`ClientSession` instance responsible for adding
                authentication headers
            path: The relative path to the API method
            data: The body of the request, to be converted to JSON

        Returns:
            the decoded JSON response
        """
        url = self.get_api_url(path)
        LOGGER.debug("post_json: %s", url)
        try:
            response = await self._http_client.post(url, json=data)
        except aiohttp.ClientError as e:
            response = e
        await _handle_request_error('post_json', response)
        return await response.json()

    async def __aenter__(self):
        await self._http_client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self._http_client.__aexit__(exc_type, exc_value, traceback)
