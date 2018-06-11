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
from typing import Mapping

from didauth.ext.aiohttp import SignedRequest, SignedRequestAuth

from .base import (
    Exchange,
    ServiceBase,
    ServiceError,
    ServiceRequest,
    ServiceResponse)
from .indy import (
    IndyRegisterIssuerReq, IndyIssuerStatus,
    IndyCreateCredOfferReq, IndyCredOffer,
    IndyCreateCredentialReq, IndyCredential,
)
from .schema import Schema, SchemaManager
from .tob import TobClient, TobClientError
from .util import log_json

LOGGER = logging.getLogger(__name__)


def load_cred_request(cred_type: Mapping, request: Mapping, validate=True) -> dict:
    """
    Convert a dictionary of input parameters into a set of only defined credential
    attributes, and optionally validate the credential format

    Args:
        cred_type: the credential type definition
        request: the claim attribute values
        validate: Whether to validate the credential against its schema value restrictions

    Returns:
        The loaded credential attributes
    """
    cred = {}
    for attr in cred_type["schema"].attr_names:
        cred[attr] = request.get(attr)
    if validate:
        cred_type["schema"].validate(cred)
    return cred


def load_cred_definitions(values: list, schema_mgr: SchemaManager) -> list:
    """
    Load the credential types defined by our config into a standard format
    """
    cred_types = []
    for ctype in values or []:
        if "schema" not in ctype:
            raise ValueError("Credential type must define 'schema'")
        if isinstance(ctype["schema"], str):
            name = ctype["schema"]
            version = None
            attributes = None
        elif isinstance(ctype["schema"], dict):
            name = ctype["schema"].get("name")
            version = ctype["schema"].get("version")
            attributes = ctype["schema"].get("attributes")
        else:
            raise ValueError("Credential type schema must be string or dict")
        if not name:
            raise ValueError("Credential type schema missing 'name'")
        if not version or not attributes:
            schema = schema_mgr.find(name, version)
            if schema:
                version = schema.version
                attributes = schema.attr_names
            else:
                raise ValueError(
                    "Schema definition not found: {} {}".format(name, version)
                )
        else:
            schema = Schema(name, version, attributes)
        cred_types.append(
            {
                "description": ctype.get("description"),
                "issuer_url": ctype.get("issuer_url"),
                "schema": schema,
            }
        )
    return cred_types


class IssuerError(ServiceError):
    """
    A message class for issues handling messages in the IssuerManager
    """
    pass


class ResolveSchemaRequest(ServiceRequest):
    """
    The message class representing an request to resolve a schema
    """
    _fields = (
        ('schema_name', str),
        ('schema_version', str, None),
        ('issuer_id', str, None),
    )


class ResolveSchemaResponse(ServiceResponse):
    """
    The message class representing the response to a schema resolution request
    """
    _fields = (
        ('issuer_id', str),
        ('schema', Schema),
        ('issuer_did', str),
    )


class IssueCredRequest(ServiceRequest):
    """
    The message class representing a request to issue a credential
    """
    _fields = (
        ('schema_name', str),
        ('schema_version', str),
        ('attributes', Mapping),
        ('issuer_id', str, None),
    )


class IssueCredResponse(ServiceResponse):
    """
    The message class representing the response from a IssueCredRequest
    """
    _fields = (
        ('issuer_id', str),
        ('cred', IndyCredential),
        'value',
    )


class IssuerService:
    """
    Manage configuration and status for a single issuer
    """

    def __init__(self, config: dict, schema_mgr: SchemaManager):
        self.api_url = None
        self.config = None
        self.cred_types = []
        self.did = None
        self.endpoint = None
        self.status = {"api": False, "ledger": False, "ready": False}
        self.wallet_seed = None
        self.load_config(config, schema_mgr)

    def load_config(self, config: dict, schema_mgr: SchemaManager):
        """
        Load a standard issuer configuration and resolve references to schemas
        """
        self.config = config
        self.api_url = config.get("api_url")
        self.cred_types = load_cred_definitions(
            config.get("credential_types"), schema_mgr
        )
        self.endpoint = config.get("url")
        wallet = config.get("wallet")
        if wallet:
            self.wallet_seed = wallet.get("seed")

    def find_cred_type(self, schema_name: str, schema_version: str = None):
        """
        Look up a defined credential type given the schema name and version

        Args:
            schema_name: the unique schema identifier
            schema_version: the schema version number

        Returns:
            the credential type definition, if found, otherwise None
        """
        for ctype in self.cred_types:
            if ctype["schema"].name == schema_name and (
                    not schema_version or ctype["schema"].version == schema_version
                ):
                return ctype
        return None

    def get_ledger_config(self, manager_pid: str) -> dict:
        """
        Get a dictionary of configuration parameters used to define an issuer for the
        ledger service
        """
        return {
            "endpoint": self.endpoint,
            "id": self.config["id"],
            "manager_pid": manager_pid,
            "schemas": [ctype["schema"] for ctype in self.cred_types],
            "wallet": self.config["wallet"],
        }

    def update_ledger_status(self, status: dict):
        """
        Update our status in reponse to a status update from the ledger service
        """
        self.did = status["did"]
        self.status["ledger"] = status["synced"]
        self.update_ready()

    def update_ready(self):
        """
        Update our ready status based on the current ledger and API sync status
        """
        self.status["ready"] = self.status["ledger"] and self.status["api"]


class IssuerManager(ServiceBase):
    """
    There should only be one instance of this class in the application.
    It is responsible for starting the issuer services and directing schema and
    credential requests to the right issuer.

    During synchronization, the IssuerManager:

        - Submits schemas and credential definitions to the ledger
        - Resolves the DID for the TheOrgBook if necessary
        - Initializes the OrgBook with our issuer information
    """

    def __init__(self, pid: str, exchange: Exchange, env: Mapping):
        super(IssuerManager, self).__init__(pid, exchange, env)
        self._issuers = {}
        self._ledger_pid = "indy-ledger"

    def add_issuer(self, issuer: IssuerService) -> None:
        """
        Add a new issuer service to the manager. This must be called before
        starting the service
        """
        self._issuers[issuer.config["id"]] = issuer

    async def _service_start(self) -> bool:
        """
        Initial service startup; submit all registered issuers to the ledger service
        for synchronization
        """
        for issuer_id, issuer in self._issuers.items():
            LOGGER.info("Registering issuer: %s", issuer_id)
            msg = IndyRegisterIssuerReq(
                issuer.get_ledger_config(self.pid)
            )
            reply = await self.submit(self._ledger_pid, msg)
            if not isinstance(reply, IndyIssuerStatus):
                raise RuntimeError(
                    "Error registering issuer {}: {}".format(issuer_id, reply)
                )
        return True

    async def _service_sync(self) -> bool:
        """
        Perform the issuer initialization process, adding any registered issuers to the
        ledger and registering them with the API client once the ledger sync has completed
        """
        synced = True
        for issuer_id, issuer in self._issuers.items():
            if issuer.status["ledger"] and not issuer.status["ready"]:
                async with self._init_api_client(issuer_id) as api_client:
                    cfg = issuer.config.copy()
                    cfg["did"] = issuer.did
                    cfg["credential_types"] = issuer.cred_types
                    try:
                        _result = await api_client.register_issuer(cfg)
                        issuer.status["ready"] = True
                        if "sync_error" in issuer.status:
                            del issuer.status["sync_error"]
                        LOGGER.info("Issuer %s registered with API", issuer_id)
                    except TobClientError as e:
                        issuer.status["sync_error"] = str(e)
                        LOGGER.error("Issuer %s API registration failed: %s",
                                     issuer_id, str(e))
            if not issuer.status["ready"]:
                synced = False
        return synced

    def _find_issuer_for_schema(self, schema_name: str, schema_version: str = None):
        """
        Find the issuer for a particular schema and version

        Args:
            schema_name: the name of the schema as identifier on the ledger
            schema_version: the version number of the schema

        Returns:
            a tuple of the :class:`IssuerService` instance and credential type definition, or None
        """
        for issuer_id, issuer in self._issuers.items():
            cred_type = issuer.find_cred_type(schema_name, schema_version)
            if cred_type:
                return (issuer_id, cred_type)
        return None

    async def _handle_issue_cred(self, request: IssueCredRequest):
        """
        Submit a credential to the holder

        Args:
            request: a message representing the credential information

        Returns:
            the decoded JSON result of the credential submission request
        """
        errmsg = None
        if not self._status["synced"]:
            errmsg = IssuerError("Issuer manager is not synced")
        elif not request.schema_name:
            errmsg = IssuerError("Missing schema name")
        elif not request.attributes:
            errmsg = IssuerError("Missing credential attributes")
        if errmsg:
            return errmsg

        issuer_id = request.issuer_id
        if issuer_id:
            if issuer_id not in self._issuers:
                return IssuerError("Unknown issuer ID: {}".format(issuer_id))
            cred_type = self._issuers[issuer_id].find_cred_type(
                request.schema_name, request.schema_version
            )
        else:
            found = self._find_issuer_for_schema(
                request.schema_name, request.schema_version
            )
            if found:
                issuer_id, cred_type = found
            else:
                cred_type = None

        if not cred_type:
            return IssuerError(
                "Error locating credential type: {}/{}".format(
                    request.schema_name, request.schema_version
                )
            )

        cred_data = load_cred_request(cred_type, request.attributes)
        log_json("Credential data:", cred_data, LOGGER)

        async with self._init_api_client(issuer_id) as api_client:
            reply = await self._issue_cred(
                api_client, issuer_id, cred_type, cred_data
            )
            msg = IssueCredResponse(issuer_id, reply.cred, reply.result)
        return msg

    async def _issue_cred(self, api_client: TobClient, issuer_id: str,
                          cred_type, cred_data) -> dict:
        """
        Submit a credential to the holder, given the credential type and data

        Args:
            api_client: the HTTP client (responsible for signing headers)
            cred_type: the credential type information
            cred_data: the prepared credential data

        Returns:
            the decoded JSON result of the credential submission request
        """
        offer_msg = IndyCreateCredOfferReq(issuer_id, cred_type["schema"])
        cred_offer = await self.submit(self._ledger_pid, offer_msg)
        if not isinstance(cred_offer, IndyCredOffer):
            raise ValueError(
                "Unexpected response to credential offer request: {}".format(
                    cred_offer
                )
            )
        log_json("Created cred offer:", cred_offer, LOGGER)

        cred_req = await api_client.generate_credential_request(cred_offer)
        log_json("Got cred request:", cred_req, LOGGER)

        cred_msg = IndyCreateCredentialReq(
            cred_offer,
            cred_req.result,
            cred_req.metadata,
            cred_data)
        cred = await self.submit(self._ledger_pid, cred_msg)
        if not isinstance(cred, IndyCredential):
            raise ValueError(
                "Unexpected response to credential creation request: {}".format(
                    cred
                )
            )
        log_json("Created credential:", cred, LOGGER)

        return await api_client.store_credential(cred)

    def _init_api_client(self, issuer_id: str):
        """
        Initialize a :class:`TobClient` instance with the required settings for this issuer

        Args:
            the unique identifier of the issuer service
        Returns:
            the initialized :class:`TobClient` instance
        """
        return TobClient(
            self._issuer_http_client(issuer_id),
            self._issuers[issuer_id].api_url)

    def _issuer_http_client(self, issuer_id: str = None, **kwargs):
        """
        Create a new :class:`ClientSession` which includes DID signing information in each request

        Args:
            an optional identifier for a specific issuer service (to enable DID signing)
        Returns:
            the initialized :class:`ClientSession` object
        """
        if "request_class" not in kwargs:
            kwargs["request_class"] = SignedRequest
        if issuer_id and "auth" not in kwargs:
            kwargs["auth"] = self._did_auth(issuer_id)
        return super(IssuerManager, self).http_client(**kwargs)

    def _did_auth(self, issuer_id: str, header_list=None):
        """
        Create a :class:`SignedRequestAuth` representing our authentication credentials,
        used to sign outgoing requests

        Args:
            issuer_id: the unique identifier of the issuer
            header_list: optionally override the list of headers to sign
        """
        if issuer_id not in self._issuers:
            raise ValueError("Unknown issuer ID: {}".format(issuer_id))
        issuer = self._issuers[issuer_id]
        if issuer.did and issuer.wallet_seed:
            key_id = "did:sov:{}".format(issuer.did)
            secret = issuer.wallet_seed
            if isinstance(secret, str):
                secret = secret.encode("ascii")
            return SignedRequestAuth(key_id, "ed25519", secret, header_list)
        return None

    async def _service_request(self, request: ServiceRequest) -> ServiceResponse:
        """
        Process a request from the exchange and send the reply, if any

        Args:
            request: The request to be processed
        """
        if isinstance(request, ResolveSchemaRequest):
            found = self._find_issuer_for_schema(
                request.schema_name, request.schema_version
            )
            if found:
                issuer_id = found[0]
                issuer_did = self._issuers[issuer_id].did
                schema = found[1]["schema"]
                reply = ResolveSchemaResponse(found[0], schema, issuer_did)
            else:
                reply = IssuerError("No issuer found for schema")

        elif isinstance(request, IssueCredRequest):
            reply = await self._handle_issue_cred(request)

        else:
            reply = None
        return reply

    async def _service_response(self, response: ServiceResponse) -> bool:
        if isinstance(response, IndyIssuerStatus):
            self._issuers[response.issuer_id].update_ledger_status(
                response.status
            )
            self.run_task(self._sync())
            return True
        return False
