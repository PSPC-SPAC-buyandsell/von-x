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
Message classes used to communicate with the :class:`IndyService`
"""

from typing import Sequence

from ..common.service import (
    ServiceAck,
    ServiceFail,
    ServiceRequest,
    ServiceResponse,
)


class IndyServiceAck(ServiceAck):
    """
    A generic acknowledgement in response to an Indy service request
    """
    pass


class IndyServiceFail(ServiceFail):
    """
    For generic errors in processing Indy requests
    """
    pass

class IndyServiceReq(ServiceRequest):
    """
    A generic Indy service request base class
    """
    pass

class IndyServiceRep(ServiceResponse):
    """
    A generic Indy service response base class
    """
    pass


class LedgerStatusReq(IndyServiceReq):
    """
    A request to fetch the status of the remote ledger
    """
    pass

class LedgerStatus(IndyServiceRep):
    """
    The response to a ledger status request
    """
    _fields = (
        "status",
    )


class RegisterWalletReq(IndyServiceReq):
    """
    A request to register a wallet
    """
    _fields = (
        ("config", dict),
    )

class WalletStatusReq(IndyServiceReq):
    """
    A request for a wallet status update
    """
    _fields = (
        ("wallet_id", str),
    )

class WalletStatus(IndyServiceRep):
    """
    A wallet status update
    """
    _fields = (
        ("wallet_id", str),
        ("status", dict),
    )


class RegisterAgentReq(IndyServiceReq):
    """
    A request to register an agent
    """
    _fields = (
        ("agent_type", str),
        ("wallet_id", str),
        ("config", dict),
    )

class AgentStatusReq(IndyServiceReq):
    """
    A request for an agent status update
    """
    _fields = (
        ("agent_id", str),
    )

class AgentStatus(IndyServiceRep):
    """
    An agent status update
    """
    _fields = (
        ("agent_id", str),
        ("status", dict),
    )


class RegisterCredentialTypeReq(IndyServiceReq):
    """
    A request to register a schema for publishing
    """
    _fields = (
        ("issuer_id", str),
        ("schema_name", str),
        ("schema_version", str),
        ("origin_did", str),
        ("attr_names", Sequence),
        ("config", dict),
    )


class RegisterConnectionReq(IndyServiceReq):
    """
    A request to register a connection
    """
    _fields = (
        ("connection_type", str),
        ("agent_id", str),
        ("config", dict),
    )

class ConnectionStatusReq(IndyServiceReq):
    """
    A request for a connection status update
    """
    _fields = (
        ("connection_id", str),
    )

class ConnectionStatus(IndyServiceRep):
    """
    A connection status update
    """
    _fields = (
        ("connection_id", str),
        ("status", dict),
    )


class IssueCredentialReq(IndyServiceReq):
    """
    Issue a credential via a previously-registered connection
    """
    _fields = (
        ("connection_id", str),
        ("schema_name", str),
        ("schema_version", str),
        ("origin_did", str),
        ("cred_data", dict),
    )


class IssueCredentialBatchReq(IndyServiceReq):
    """
    Issue a credential via a previously-registered connection
    """
    _fields = (
        ("connection_id", str),
        ("schema_name", str),
        ("schema_version", str),
        ("origin_did", str),
        ("cred_data", Sequence),
    )


class CredentialOffer(IndyServiceRep):
    """
    A successful credential offer response
    Args:
        data (dict): the resulting credential offer
    """
    _fields = (
        ("data", dict),
        ("cred_def_id", str),
    )


class CredentialRequest(IndyServiceRep):
    """
    A successful credential request response
    Args:
        cred_offer (CredentialOffer): the credential offer used as a basis
        data (str): the resulting credential request
        metadata (dict): the credential request metadata
    """
    _fields = (
        ("cred_offer", CredentialOffer),
        ("data", str),
        ("metadata", dict),
    )


class Credential(IndyServiceRep):
    """
    A successful credential creation
    """
    _fields = (
        ("cred_data", dict),
        ("cred_req_metadata", dict),
        ("cred_revoc_id", str),
    )


class StoredCredential(IndyServiceRep):
    """
    A successful response to storing a credential
    """
    _fields = (
        ("cred", Credential),
        ("cred_id", str),
        ("served_by", str, None),
    )


class StoredCredentialBatch(IndyServiceRep):
    """
    A successful response to storing a credential batch
    """
    _fields = (
        ("results", Sequence), # Sequence[StoredCredential]
        ("errors", Sequence), # Sequence[str]
    )


class GenerateCredentialRequestReq(IndyServiceReq):
    """
    A request to generate a credential request
    """
    _fields = (
        ("holder_id", str),
        ("cred_offer", CredentialOffer),
    )


class StoreCredentialReq(IndyServiceReq):
    """
    A request to store a new credential
    """
    _fields = (
        ("holder_id", str),
        ("credential", Credential),
    )


class ResolveSchemaReq(IndyServiceReq):
    """
    A request to resolve a schema which may be defined by one of our issuers
    """
    _fields = (
        ("schema_name", str),
        ("schema_version", str),
        ("origin_did", str),
    )


class ResolvedSchema(IndyServiceRep):
    """
    A request to resolve a schema which may be defined by one of our issuers
    """
    _fields = (
        ("issuer_id", str),
        ("schema_id", str),
        ("schema_name", str),
        ("schema_version", str),
        ("origin_did", str),
        ("attr_names", Sequence),
    )


class ProofRequest(IndyServiceRep):
    """
    A message representing an Indy proof request
    """
    _fields = (
        ("data", dict),
        ("wql_filters", dict, None),
    )


class ConstructProofReq(IndyServiceReq):
    """
    A request to construct a proof from a proof request
    """
    _fields = (
        ("holder_id", str),
        ("proof_req", ProofRequest),
        ("cred_ids", set),
    )


class ConstructedProof(IndyServiceRep):
    """
    A successfully constructed proof
    """
    _fields = (
        ("proof", dict),
    )


class RegisterProofSpecReq(IndyServiceReq):
    """
    A request to register a proof request specification
    """
    _fields = (
        ("config", dict),
    )


class ProofSpecStatus(IndyServiceRep):
    """
    The proof specification status update
    """
    _fields = (
        ("spec_id", str),
        ("status", dict),
    )


class GenerateProofRequestReq(IndyServiceReq):
    """
    A request to generate a proof request
    """
    _fields = (
        ("spec_id", str),
        ("wql_filters", dict, None),
    )


class RequestProofReq(IndyServiceReq):
    """
    A request to get a proof from a connection
    """
    _fields = (
        ("connection_id", str),
        ("proof_req", ProofRequest),
        ("cred_ids", set),
        ("params", dict),
    )


class VerifyProofReq(IndyServiceReq):
    """
    The message class representing a request to verify a proof
    """
    _fields = (
        ("verifier_id", str),
        ("proof_req", ProofRequest),
        ("proof", ConstructedProof),
    )


class VerifiedProof(IndyServiceRep):
    """
    The message class representing a successful proof verification
    """
    _fields = (
        ("verified", str),
        ("parsed_proof", dict),
        ("proof", ConstructedProof),
    )

class ResolveNymReq(IndyServiceReq):
    """
    The message class representing a request to resolve a DID
    """
    _fields = (
        ("did", str),
        ("agent_id", str, None),
    )

class ResolvedNym(IndyServiceRep):
    """
    The message class representing a DID resolution response
    """
    _fields = (
        ("did", str),
        ("data", dict),
    )
