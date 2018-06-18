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

from .messages import (
    CredentialOffer,
    Credential,
    CredentialRequest,
    StoredCredential)


class ConnectionType(Enum):
    TheOrgBook = "TheOrgBook"
    vonx = "von-x"


class ConnectionBase:
    def __init__(self, http_client, agent_params: dict, conn_params: dict):
        pass

    async def open(self) -> None:
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

    async def construct_proof(self, proof_request: dict):
        """
        Ask the target to construct a proof from a proof request

        Args:
            proof_request: the prepared Indy proof request
        """
        pass
