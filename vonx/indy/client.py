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
:class:`IndyClient` handles message passing to the :class:`IndyService`, providing
a more natural interface for working with the ledger.
"""

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
    IssueCredentialBatchReq,
    Credential,
    CredentialOffer,
    CredentialRequest,
    StoredCredential,
    StoredCredentialBatch,
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
    VerifyProofReq,
    ResolveNymReq,
    ResolvedNym,
)

class IndyClient:
    """
    This class provides a nicer interface for passing messages to the Indy service manager
    """
    def __init__(self, target: RequestTarget):
        self._target = target

    async def _fetch(self, request: ServiceRequest, expect=None):
        """
        Send a request to the :class:`IndyService` and check the result

        Args:
            request: the request to be sent
            expect: the type or types expected in response
        """
        result = await self._target.request(request)
        if isinstance(result, IndyServiceFail):
            raise IndyClientError(result.value)
        elif expect and not isinstance(result, expect):
            raise IndyClientError("Unexpected result: {}".format(result))
        return result

    async def get_ledger_status(self):
        """
        Get the status of the remote ledger (for von-network)
        """
        result = await self._fetch(LedgerStatusReq(), LedgerStatus)
        return result.status

    async def register_wallet(self, config: dict) -> str:
        """
        Register a wallet

        Args:
            config: the wallet configuration (must include 'name' and 'seed')
        Returns:
            the registered identifier of the wallet
        """
        result = await self._fetch(RegisterWalletReq(config), WalletStatus)
        return result.wallet_id

    async def get_wallet_status(self, wallet_id: str) -> dict:
        """
        Get the status of a registered wallet

        Args:
            wallet_id: the registered wallet identifier
        """
        result = await self._fetch(WalletStatusReq(wallet_id), WalletStatus)
        return result.status

    async def register_issuer(self, wallet_id: str, config: dict) -> str:
        """
        Register an issuer service

        Args:
            wallet_id: the registered wallet identifier to use for this agent
            config: the issuer configuration
        Returns:
            the registered identifier of the issuer service
        """
        agent_type = AgentType.issuer.value
        if config and config.get("holder_verifier"):
            agent_type = AgentType.combined.value
        result = await self._fetch(
            RegisterAgentReq(agent_type, wallet_id, config),
            AgentStatus)
        return result.agent_id

    async def register_holder(self, wallet_id: str, config: dict) -> str:
        """
        Register a holder service

        Args:
            wallet_id: the registered wallet identifier to use for this agent
            config: the holder configuration
        Returns:
            the registered identifier of the holder service
        """
        result = await self._fetch(
            RegisterAgentReq(AgentType.holder.value, wallet_id, config),
            AgentStatus)
        return result.agent_id

    async def register_verifier(self, wallet_id: str, config: dict) -> str:
        """
        Register a verifier service

        Args:
            wallet_id: the registered wallet identifier to use for this agent
            config: the verifier configuration
        Returns:
            the registered identifier of the verifier service
        """
        result = await self._fetch(
            RegisterAgentReq(AgentType.verifier.value, wallet_id, config),
            AgentStatus)
        return result.agent_id

    async def get_agent_status(self, agent_id: str) -> dict:
        """
        Fetch the status of a registered agent (issuer, holder, or verifier)

        Args:
            agent_id: the registered agent identifier
        """
        result = await self._fetch(AgentStatusReq(agent_id), AgentStatus)
        return result.status

    async def register_credential_type(self, issuer_id: str,
                                       schema_name: str, schema_version: str,
                                       origin_did: str, attr_names: Sequence,
                                       config: dict = None) -> None:
        """
        Register a credential type for a previously-registered issuer

        Args:
            issuer_id: the registered agent identifier
            schema_name: the name of the schema
            schema_version: the version of the schema
            origin_did: for schemas published by other issuers, otherwise None
            attr_names: the list of attribute names, required for a schema to be published
            config: extra configuration parameters for the credential type
        """
        await self._fetch(
            RegisterCredentialTypeReq(
                issuer_id, schema_name, schema_version,
                origin_did, attr_names, config),
            IndyServiceAck)

    async def register_http_connection(self, agent_id: str, config: dict = None) -> str:
        """
        Register an HTTP connection to a holder/prover service

        Args:
            agent_id: the registered issuer or verifier agent identifier
            config: configuration parameters for the connection (must include 'api_url')
        """
        result = await self._fetch(
            RegisterConnectionReq(ConnectionType.HTTP.value, agent_id, config or {}),
            ConnectionStatus)
        return result.connection_id

    async def register_orgbook_connection(self, agent_id: str, config: dict = None) -> str:
        """
        Register a connection to TheOrgBook as a holder/prover

        Args:
            agent_id: the registered issuer or verifier agent identifier
            config: configuration parameters for the connection (must include 'api_url')
        """
        result = await self._fetch(
            RegisterConnectionReq(ConnectionType.TheOrgBook.value, agent_id, config or {}),
            ConnectionStatus)
        return result.connection_id

    async def register_holder_connection(self, agent_id: str, config: dict = None) -> str:
        """
        Register a connection to a local holder agent

        Args:
            agent_id: the identifier of the issuer or verifier connecting to this holder
            config: extra configuration parameters for the connection (must include 'holder_id')
        """
        result = await self._fetch(
            RegisterConnectionReq(ConnectionType.holder.value, agent_id, config or {}),
            ConnectionStatus)
        return result.connection_id

    async def get_connection_status(self, connection_id: str) -> dict:
        """
        Fetch the status of a registered connection

        Args:
            connection_id: the registered connection identifier
        """
        result = await self._fetch(ConnectionStatusReq(connection_id), ConnectionStatus)
        return result.status

    async def issue_credential(self, connection_id: str, schema_name: str, schema_version: str,
                               origin_did: str, cred_data: dict) -> StoredCredential:
        """
        Issue a credential to a previously-registered connection

        Args:
            connection_id: the registered connection identifier
            schema_name: the name of the schema, used to identify the credential type
            schema_version: the version of the schema
            origin_did: the origin DID of the schema, if external
            cred_data: the new credential's raw claim attribute values
        """
        return await self._fetch(
            IssueCredentialReq(
                connection_id, schema_name, schema_version, origin_did, cred_data),
            StoredCredential)

    async def issue_credential_batch(
            self, connection_id: str, schema_name: str, schema_version: str,
            origin_did: str, cred_data: Sequence[dict]) -> StoredCredentialBatch:
        """
        Issue a list of credentials to a previously-registered connection

        Args:
            connection_id: the registered connection identifier
            schema_name: the name of the schema, used to identify the credential type
            schema_version: the version of the schema
            origin_did: the origin DID of the schema, if external
            cred_data: the list of new credential's raw claim attribute values
        """
        return await self._fetch(
            IssueCredentialBatchReq(
                connection_id, schema_name, schema_version, origin_did, cred_data),
            StoredCredentialBatch)

    async def create_credential_request(self, holder_id: str, cred_offer: dict,
                                        cred_def_id: str) -> CredentialRequest:
        """
        Create a credential request for an issuer service

        Args:
            holder_id: the registered agent identifier of the holder service
            cred_offer: the Indy credential offer received from the issuer
            cred_def_id: The identifier of the credential definition
        """
        return await self._fetch(
            GenerateCredentialRequestReq(holder_id, CredentialOffer(cred_offer, cred_def_id)),
            CredentialRequest)

    async def store_credential(self, holder_id: str,
                               credential: Credential) -> StoredCredential:
        """
        Store a credential in a holder's wallet

        Args:
            holder_id: the registered agent identifier
            credential: the Indy credential record
        """
        return await self._fetch(
            StoreCredentialReq(holder_id, credential),
            StoredCredential)

    async def resolve_schema(self, name: str, version: str = None,
                             origin_did: str = None) -> ResolvedSchema:
        """
        Resolve a schema from a registered credential type or the ledger

        Args:
            name: the schema name
            version: the schema version
            origin_did: the DID of the schema issuer
        """
        return await self._fetch(
            ResolveSchemaReq(name, version, origin_did),
            ResolvedSchema)

    async def construct_proof(self, holder_id: str, proof_req: dict,
                              wql_filters: dict = None, cred_ids: set = None) -> ConstructedProof:
        """
        Construct a proof from credentials in the holder's wallet given a proof request

        Args:
            holder_id: the registered agent identifier
            proof_req: the Indy proof request record
            cred_ids: an optional set of credential IDs to use in the proof
        """
        return await self._fetch(
            ConstructProofReq(holder_id, ProofRequest(proof_req, wql_filters), cred_ids),
            ConstructedProof)

    async def register_proof_spec(self, spec: dict) -> str:
        """
        Register a proof request specification

        Args:
            spec: the proof request specification
        Returns:
            the identifier of the registered proof request spec
        """
        result = await self._fetch(
            RegisterProofSpecReq(spec),
            ProofSpecStatus)
        return result.spec_id

    async def generate_proof_request(self, spec_id: str) -> ProofRequest:
        """
        Generate a proof request based on a previously-registered proof request spec

        Args:
            spec_id: the registered proof request spec identifier
        """
        return await self._fetch(
            GenerateProofRequestReq(spec_id),
            ProofRequest)

    async def request_proof(self, connection_id: str, proof_req: ProofRequest,
                            cred_ids: set = None, params: dict = None) -> ConstructedProof:
        """
        Request a proof from a holder connection

        Args:
            connection_id: the registered holder connection
            proof_req: the Indy proof request record
            cred_ids: an optional set of credential IDs to use in the proof
            params: extra parameters for the connection to use in the proof construction
        """
        return await self._fetch(
            RequestProofReq(connection_id, proof_req, cred_ids, params),
            VerifiedProof)

    async def verify_proof(self, verifier_id: str, proof_req: ProofRequest,
                           proof: ConstructedProof) -> VerifiedProof:
        """
        Verify a previously constructed proof

        Args:
            verifier_id: the registered verifier agent
            proof_req: the Indy proof request record
            proof: the constructed proof
        """
        return await self._fetch(
            VerifyProofReq(verifier_id, proof_req, proof),
            VerifiedProof)

    async def resolve_nym(self, did: str, agent_id: str = None):
        """
        Resolve a DID on the ledger

        Args:
            did: the DID to resolve
            agent_id: the agent instance to use
        """
        return await self._fetch(
            ResolveNymReq(did, agent_id),
            ResolvedNym)

    async def sync(self, wait: bool = True) -> bool:
        """
        Request the :class:`IndyService` to perform synchronization of registered services

        Args:
            wait: whether to return immediately or wait for the sync to finish
        """
        result = await self._fetch(
            ServiceSyncReq(wait))
        if isinstance(result, ServiceAck):
            return True
        return False

    async def get_status(self) -> dict:
        """
        Fetch the status of the :class:`IndyService` and its registered services
        """
        result = await self._fetch(
            ServiceStatusReq(),
            ServiceStatus)
        return result.status
