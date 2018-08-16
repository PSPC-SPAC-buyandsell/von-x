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
Base implemention of Connections, to be managed by :class:`ConnectionCfg`.
"""

import asyncio
from enum import Enum
import logging

import aiohttp

from ..common.exchange import RequestTarget
from .errors import IndyConfigError, IndyConnectionError
from .messages import (
    IndyServiceFail,
    CredentialOffer,
    Credential,
    GenerateCredentialRequestReq,
    CredentialRequest,
    StoreCredentialReq,
    StoredCredential,
    ProofRequest,
    ConstructProofReq,
    ConstructedProof,
)

LOGGER = logging.getLogger(__name__)


class ConnectionType(Enum):
    """
    Enumeration of supported connection types
    """
    TheOrgBook = "TheOrgBook"
    holder = "holder"
    HTTP = "HTTP"


class HttpSession:
    """
    Handle an exception or bad response from an HTTP request
    """

    def __init__(self, method: str, http_client: aiohttp.ClientSession = None, timeout=None):
        self._client = http_client
        self._method = method
        self._opened = False
        self._timeout = timeout

    @property
    def client(self) -> aiohttp.ClientSession:
        """
        Accessor for the :class:`ClientSession` instance
        """
        return self._client

    async def check_status(self, response: aiohttp.ClientResponse, accept=(200, 201)):
        """
        Check the HTTP status of a response to a previous request
        """
        if response.status not in accept:
            raise IndyConnectionError(
                "Bad response from {}: ({}) {}".format(
                    self._method, response.status, await response.text()
                ),
                response.status,
                response,
            )

    async def __aenter__(self) -> 'ErrorHandler':
        if not self._client:
            self._client = aiohttp.ClientSession(read_timeout=self._timeout)
            self._opened = True
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        if self._opened:
            await self._client.close()
        if exc_type == IndyConnectionError:
            return False
        if exc_type == asyncio.TimeoutError:
            raise IndyConnectionError(
                "Connection timed out during {}".format(self._method),
                status=598,
            ) from None
        if exc_value:
            code = getattr(exc_value, 'code', None)
            raise IndyConnectionError(
                "Exception during {}: {} ({})".format(self._method, str(exc_value), code),
                status=code,
            ) from None


class ConnectionBase:
    """
    Base interface for Connection implementations
    """

    def __init__(self, agent_id: str, agent_type: str, agent_params: dict, conn_params: dict):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.agent_params = agent_params
        self.conn_params = conn_params
        self.created = False
        self.opened = False
        self.synced = False

    async def open(self, service: 'IndyService') -> None:
        """
        Initialize the connection
        """
        pass

    async def sync(self) -> None:
        """
        Perform any required synchronization
        """
        pass

    async def generate_credential_request(
            self, indy_offer: CredentialOffer) -> CredentialRequest:
        """
        Ask the target to generate a credential request from our credential offer

        Args:
            indy_offer: the result of preparing a credential offer
            creddef_id: the ID of the credential definition
        """
        pass

    async def store_credential(
            self, indy_cred: Credential) -> StoredCredential:
        """
        Ask the target to store a credential

        Args:
            indy_cred: the result of preparing a credential from a credential request
        """
        pass

    async def construct_proof(self, request: ProofRequest,
                              cred_ids: set = None, params: dict = None) -> ConstructedProof:
        """
        Ask the target to construct a proof from a proof request

        Args:
            request: the prepared Indy proof request
            params: extra parameters for the API
        """
        pass

    async def close(self) -> None:
        """
        Shut down the connection
        """
        pass


class HolderConnection(ConnectionBase):
    """
    :class:`ConnectionBase` interface implementation for local holder services
    """

    def __init__(self, agent_id: str, agent_type: str, agent_params: dict, conn_params: dict):
        super(HolderConnection, self).__init__(agent_id, agent_type, agent_params, conn_params)
        self.holder_id = self.conn_params.get("holder_id")
        if not self.holder_id:
            raise IndyConfigError("Missing 'holder_id' for holder connection")
        self.target = None

    async def open(self, service: 'IndyService') -> None:
        """
        Initialize the connection
        """
        self.target = RequestTarget(service, service.pid)

    async def close(self) -> None:
        """
        Shut down the connection
        """
        self.target = None

    async def generate_credential_request(
            self, indy_offer: CredentialOffer) -> CredentialRequest:
        """
        Ask the target to generate a credential request from our credential offer

        Args:
            indy_offer: the result of preparing a credential offer
        """
        result = await self.target.request(
            GenerateCredentialRequestReq(self.holder_id, indy_offer))
        if isinstance(result, IndyServiceFail):
            raise IndyConnectionError(result.value, 500)
        elif not isinstance(result, CredentialRequest):
            raise IndyConnectionError("Unexpected result: {}".format(result), 500)
        return result

    async def store_credential(
            self, indy_cred: Credential) -> StoredCredential:
        """
        Ask the target to store a credential

        Args:
            indy_cred: the result of preparing a credential from a credential request
        """
        result = await self.target.request(
            StoreCredentialReq(self.holder_id, indy_cred))
        if isinstance(result, IndyServiceFail):
            raise IndyConnectionError(result.value, 500)
        elif not isinstance(result, StoredCredential):
            raise IndyConnectionError("Unexpected result: {}".format(result), 500)
        return result

    async def construct_proof(self, request: ProofRequest,
                              cred_ids: set = None, params: dict = None) -> ConstructedProof:
        """
        Ask the target to construct a proof from a proof request

        Args:
            request: the prepared Indy proof request
            params: extra parameters for the API
        """
        result = await self.target.request(
            ConstructProofReq(self.holder_id, request, cred_ids))
        if isinstance(result, IndyServiceFail):
            raise IndyConnectionError(result.value, 500)
        elif not isinstance(result, ConstructedProof):
            raise IndyConnectionError("Unexpected result: {}".format(result), 500)
        return result


class HttpConnection(ConnectionBase):
    """
    A class for managing communication with an external agent over an HTTP connection
    """

    def __init__(self, agent_id: str, agent_type: str, agent_params: dict, conn_params: dict):
        super(HttpConnection, self).__init__(agent_id, agent_type, agent_params, conn_params)
        self._api_url = self.conn_params.get("api_url")
        if not self._api_url:
            raise IndyConfigError("Missing 'api_url' for HTTP connection")
        self._http_client = None

    async def open(self, service: "IndyService") -> None:
        # TODO check DID is registered etc ..
        self._http_client = service._connection_http_client(self.conn_params["id"])

    async def close(self) -> None:
        """
        Shut down the connection
        """
        if self._http_client:
            await self._http_client.close()
            self._http_client = None

    @property
    def path_prefix(self):
        return ''

    async def generate_credential_request(
            self, indy_offer: CredentialOffer) -> CredentialRequest:
        """
        Ask the API to generate a credential request from our credential offer

        Args:
            indy_offer: the result of preparing a credential offer
        """
        response = await self.post_json(
            self.path_prefix + "generate-credential-request", {
                "credential_offer": indy_offer.data,
                "credential_definition_id": indy_offer.cred_def_id,
            }
        )
        LOGGER.debug("Credential request response: %s", response)
        result = response.get("result")
        if not response.get("success"):
            raise IndyConnectionError(
                "Could not create credential request: {}".format(result),
                400,
                response,
            )
        return CredentialRequest(
            indy_offer,
            result["credential_request"],
            result["credential_request_metadata"],
        )

    async def store_credential(
            self, indy_cred: Credential) -> StoredCredential:
        """
        Ask the API to store a credential

        Args:
            indy_cred: the result of preparing a credential from a credential request
        """
        schema_id = indy_cred.cred_data["schema_id"]
        cred_def_id = indy_cred.cred_data["cred_def_id"]
        response = await self.post_json(
            self.path_prefix + "store-credential", {
                # "credential_type": schema_id.split(':')[2],
                # "issuer_did": cred_def_id.split(':')[0],
                # "credential_definition": indy_cred.cred_def,
                "credential_data": indy_cred.cred_data,
                "credential_request_metadata": indy_cred.cred_req_metadata,
            }
        )
        LOGGER.debug("Store credential response: %s", response)
        result = response.get("result")
        if not response.get("success"):
            raise IndyConnectionError(
                "Credential was not stored: {}".format(result),
                400,
                response,
            )
        return StoredCredential(
            indy_cred,
            result,
        )

    async def construct_proof(self, request: ProofRequest,
                              cred_ids: set = None, params: dict = None) -> ConstructedProof:
        """
        Ask the API to construct a proof from a proof request

        Args:
            proof_request: the prepared Indy proof request
        """
        response = await self.post_json(
            self.path_prefix + "construct-proof", {
                "source_id": params and params.get("source_id") or None,
                "proof_request": request.data,
                "cred_ids": list(cred_ids) if cred_ids else None,
            }
        )
        result = response.get("result")
        if not response.get("success"):
            raise IndyConnectionError(
                "Error constructing proof: {}".format(result),
                400,
                response,
            )
        return ConstructedProof(
            result,
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
        async with HttpSession("post_json", self._http_client) as handler:
            response = await handler.client.post(url, json=data)
            await handler.check_status(response)
            return await response.json()
