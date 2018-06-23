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

from typing import Sequence

from ..common.exchange import RequestTarget
from ..common.service import (
    ServiceAck,
    ServiceRequest,
    ServiceSyncReq,
    ServiceStatusReq,
    ServiceStatus,
)

from .config import AgentType, ConnectionType
from .errors import IndyClientError

from .messages import (
    IndyServiceAck,
    IndyServiceFail,
    LedgerStatusReq,
    LedgerStatus,
    RegisterWalletReq,
    WalletStatusReq,
    WalletStatus,
    RegisterAgentReq,
    AgentStatusReq,
    AgentStatus,
    RegisterCredentialTypeReq,
    RegisterConnectionReq,
    ConnectionStatusReq,
    ConnectionStatus,
    IssueCredentialReq,
    StoredCredential,
    CredentialOffer,
    CredentialRequest,
    Credential,
    GenerateCredentialRequestReq,
    StoreCredentialReq,
    ResolveSchemaReq,
    ResolvedSchema,
    ProofRequest,
    ConstructProofReq,
    ConstructedProof,
    GenerateProofRequestReq,
    RegisterProofSpecReq,
    ProofSpecStatus,
    VerifiedProof,
    RequestProofReq,
)

class IndyClient:
    """
    Wrap up message passing to the Indy service manager in a nicer interface
    """
    def __init__(self, target: RequestTarget):
        self._target = target

    async def _fetch(self, request: ServiceRequest, expect=None):
        result = await self._target.request(request)
        if isinstance(result, IndyServiceFail):
            raise IndyClientError(result.value)
        elif expect and not isinstance(result, expect):
            raise IndyClientError("Unexpected result: {}".format(result))
        return result

    async def get_ledger_status(self):
        result = await self._fetch(LedgerStatusReq(), LedgerStatus)
        return result.status

    async def register_wallet(self, config: dict) -> str:
        result = await self._fetch(RegisterWalletReq(config), WalletStatus)
        return result.wallet_id

    async def get_wallet_status(self, wallet_id: str) -> dict:
        result = await self._fetch(WalletStatusReq(wallet_id), WalletStatus)
        return result.status

    async def register_issuer(self, wallet_id: str, config: dict) -> str:
        result = await self._fetch(
            RegisterAgentReq(AgentType.issuer.value, wallet_id, config),
            AgentStatus)
        return result.agent_id

    async def register_holder(self, wallet_id: str, config: dict) -> str:
        result = await self._fetch(
            RegisterAgentReq(AgentType.holder.value, wallet_id, config),
            AgentStatus)
        return result.agent_id

    async def register_verifier(self, wallet_id: str, config: dict) -> str:
        result = await self._fetch(
            RegisterAgentReq(AgentType.verifier.value, wallet_id, config),
            AgentStatus)
        return result.agent_id

    async def get_agent_status(self, agent_id: str) -> dict:
        result = await self._fetch(AgentStatusReq(agent_id), AgentStatus)
        return result.status

    async def register_credential_type(self, issuer_id: str,
                                       schema_name: str, schema_version: str,
                                       origin_did: str, attr_names: Sequence,
                                       config: dict = None) -> None:
        await self._fetch(
            RegisterCredentialTypeReq(
                issuer_id, schema_name, schema_version,
                origin_did, attr_names, config),
            IndyServiceAck)

    async def register_orgbook_connection(self, agent_id: str, config: dict = None) -> str:
        result = await self._fetch(
            RegisterConnectionReq(ConnectionType.TheOrgBook.value, agent_id, config or {}),
            ConnectionStatus)
        return result.connection_id

    async def register_holder_connection(self, agent_id: str, config: dict = None) -> str:
        result = await self._fetch(
            RegisterConnectionReq(ConnectionType.holder.value, agent_id, config or {}),
            ConnectionStatus)
        return result.connection_id

    async def get_connection_status(self, connection_id: str) -> dict:
        result = await self._fetch(ConnectionStatusReq(connection_id), ConnectionStatus)
        return result.status

    async def issue_credential(
            self,
            connection_id: str,
            schema_name: str,
            schema_version: str,
            origin_did: str,
            cred_data: dict) -> (str, dict):
        stored = await self._fetch(
            IssueCredentialReq(connection_id, schema_name, schema_version, origin_did, cred_data),
            StoredCredential)
        return (stored.cred_id, stored.result)

    async def create_credential_request(self, holder_id: str,
                                        cred_offer: CredentialOffer) -> CredentialRequest:
        request = await self._fetch(
            GenerateCredentialRequestReq(holder_id, cred_offer),
            CredentialRequest)
        return request

    async def store_credential(self, holder_id: str,
                               credential: Credential) -> StoredCredential:
        stored = await self._fetch(
            StoreCredentialReq(holder_id, credential),
            StoredCredential)
        return stored

    async def resolve_schema(self, name: str, version: str = None,
                             origin_did: str = None) -> ResolvedSchema:
        found = await self._fetch(
            ResolveSchemaReq(name, version, origin_did),
            ResolvedSchema)
        return found

    async def construct_proof(self, holder_id: str, proof_req: ProofRequest) -> ConstructedProof:
        proof = await self._fetch(
            ConstructProofReq(holder_id, proof_req),
            ConstructedProof)
        return proof

    async def register_proof_spec(self, spec: dict) -> str:
        result = await self._fetch(
            RegisterProofSpecReq(spec),
            ProofSpecStatus)
        return result.spec_id

    async def generate_proof_request(self, spec_id: str) -> ProofRequest:
        request = await self._fetch(
            GenerateProofRequestReq(spec_id),
            ProofRequest)
        return request

    async def request_proof(self, connection_id: str, proof_req: ProofRequest,
                            params: dict = None) -> ConstructedProof:
        request = await self._fetch(
            RequestProofReq(connection_id, proof_req, params),
            VerifiedProof)
        return request

    async def sync(self, wait: bool = True) -> bool:
        result = await self._fetch(
            ServiceSyncReq(wait))
        if isinstance(result, ServiceAck):
            return True
        return False

    async def get_status(self) -> dict:
        result = await self._fetch(
            ServiceStatusReq(),
            ServiceStatus)
        return result.status
