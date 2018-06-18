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

from ..common.service import (
    ServiceAck,
    ServiceFail,
    ServiceRequest,
    ServiceResponse,
)


class IndyServiceAck(ServiceAck):
    pass


class IndyServiceFail(ServiceFail):
    """
    For generic errors in processing Indy requests
    """
    pass


class LedgerStatusReq(ServiceRequest):
    """
    A request to fetch the status of the remote ledger
    """
    pass

class LedgerStatus(ServiceResponse):
    """
    The response to a ledger status request
    """
    _fields = (
        "status",
    )


class RegisterWalletReq(ServiceRequest):
    """
    A request to register a wallet
    """
    _fields = (
        ("config", dict),
    )

class WalletStatusReq(ServiceRequest):
    """
    A request for a wallet status update
    """
    _fields = (
        ("wallet_id", str),
    )

class WalletStatus(ServiceResponse):
    """
    A wallet status update
    """
    _fields = (
        ("wallet_id", str),
        ("status", dict),
    )


class RegisterAgentReq(ServiceRequest):
    """
    A request to register an agent
    """
    _fields = (
        ("agent_type", str),
        ("wallet_id", str),
        ("config", dict),
    )

class AgentStatusReq(ServiceRequest):
    """
    A request for an agent status update
    """
    _fields = (
        ("agent_id", str),
    )

class AgentStatus(ServiceResponse):
    """
    An agent status update
    """
    _fields = (
        ("agent_id", str),
        ("status", dict),
    )


class RegisterCredentialTypeReq(ServiceRequest):
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


class RegisterConnectionReq(ServiceRequest):
    """
    A request to register a connection
    """
    _fields = (
        ("connection_type", str),
        ("agent_id", str),
        ("config", dict),
    )

class ConnectionStatusReq(ServiceRequest):
    """
    A request for a connection status update
    """
    _fields = (
        ("connection_id", str),
    )

class ConnectionStatus(ServiceResponse):
    """
    A connection status update
    """
    _fields = (
        ("connection_id", str),
        ("status", dict),
    )


class CredentialOffer(ServiceResponse):
    """
    A successful credential offer response
    Args:
        issuer_id (str): the identifier of the issuer service
        schema_name (str): the schema used to create the credential offer
        schema_version (str): the schema version used to create the credential offer
        offer (dict): the resulting credential offer
        cred_def (dict): the credential definition used
    """
    _fields = (
        ("issuer_id", str),
        ("schema_name", str),
        ("schema_version", str),
        ("offer", dict),
        ("cred_def", dict),
    )


class CredentialRequest(ServiceResponse):
    """
    A successful credential request response
    Args:
        holder_id (str): the identifier of the holder service
        cred_offer (IndyCredOffer): the credential offer used as a basis
        result (str): the resulting credential request
        metadata (dict): the credential request metadata
    """
    _fields = (
        ("holder_id", str),
        ("cred_offer", CredentialOffer),
        ("result", str),
        ("metadata", dict),
    )


class Credential(ServiceResponse):
    """
    A successful credential creation
    """
    _fields = (
        ("issuer_id", str),
        ("schema_name", str),
        ("issuer_did", str),
        ("cred_data", dict),
        ("cred_def", dict),
        ("cred_req_metadata", dict),
        ("cred_revoc_id", str),
    )


class StoredCredential(ServiceResponse):
    """
    A successful response to storing a credential
    """
    _fields = (
        ("holder_id", str),
        ("cred", Credential),
        ("result", dict),
    )


class IndyVerifyProofReq(ServiceRequest):
    """
    The message class representing a request to verify a proof
    """
    _fields = (
        ("proof_req", dict),
        ("proof", dict),
    )


class IndyVerifiedProof(ServiceResponse):
    """
    The message class representing a successful proof verification
    """
    _fields = (
        ("verified", str),
        ("parsed_proof", dict),
    )
