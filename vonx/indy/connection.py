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

from enum import Enum

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


class ConnectionType(Enum):
    TheOrgBook = "TheOrgBook"
    holder = "holder"
    remote = "remote"


class ConnectionBase:
    def __init__(self, agent_id: str, _agent_params: dict, _conn_params: dict):
        self.agent_id = agent_id

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


class HolderConnection(ConnectionBase):
    def __init__(self, agent_id: str, agent_params: dict, conn_params: dict):
        super(HolderConnection, self).__init__(agent_id, agent_params, conn_params)
        self.holder_id = conn_params.get("holder_id")
        if not self.holder_id:
            raise IndyConfigError("Missing 'holder_id' for holder connection")
        self.target = None

    async def open(self, service: 'IndyService') -> None:
        """
        Initialize the connection
        """
        self.target = RequestTarget(service, service.pid)

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
            raise IndyConnectionError(500, result.value)
        elif not isinstance(result, CredentialRequest):
            raise IndyConnectionError(500, "Unexpected result: {}".format(result))
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
            raise IndyConnectionError(500, result.value)
        elif not isinstance(result, StoredCredential):
            raise IndyConnectionError(500, "Unexpected result: {}".format(result))
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
            raise IndyConnectionError(500, result.value)
        elif not isinstance(result, ConstructedProof):
            raise IndyConnectionError(500, "Unexpected result: {}".format(result))
        return result
