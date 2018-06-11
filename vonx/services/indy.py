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

import asyncio
import json
import logging
import pathlib
from typing import Mapping
import uuid

import aiohttp
from didauth.indy import seed_to_did
from von_agent.agents import (
    _BaseAgent,
    Issuer as VonIssuer,
    HolderProver as VonHolderProver,
    Verifier as VonVerifier,
)
from von_agent.error import AbsentSchema, AbsentCredDef
from von_agent.nodepool import NodePool
from von_agent.wallet import Wallet
from von_agent.util import cred_def_id, revealed_attrs, schema_id, schema_key

from .base import (
    Exchange,
    ServiceBase,
    ServiceRequest,
    ServiceResponse,
    ServiceError)
from .schema import Schema
from .util import log_json

LOGGER = logging.getLogger(__name__)


class IndyLedgerError(ServiceError):
    """
    A message class for generic errors in processing Indy requests
    """
    pass


class IndyLedgerStatusReq(ServiceRequest):
    """
    A request to fetch the status of the remote ledger
    """
    pass


class IndyCreateCredOfferReq(ServiceRequest):
    """
    The message class representing an request to create a credential offer

    Args:
        issuer_id (str): the identifier of the issuer service
        schema_def (Schema): the schema used to create the credential offer
    """
    _fields = (
        ('issuer_id', str),
        ('schema_def', Schema),
    )


class IndyCredOffer(ServiceResponse):
    """
    The message class representing a successful credential offer response

    Args:
        issuer_id (str): the identifier of the issuer service
        schema_def (Schema): the schema used to create the credential offer
        offer (dict): the resulting credential offer
        cred_def (dict): the credential definition used
    """
    _fields = (
        ('issuer_id', str),
        ('schema_def', Schema),
        ('offer', dict),
        ('cred_def', dict),
    )

class IndyCreateCredRequestReq(ServiceRequest):
    """
    The message class representing an request to create a credential request

    Args:
        holder_id (str): the identifier of the holder service
        cred_offer (IndyCredOffer): the credential offer to use as a basis
    """
    _fields = (
        ('holder_id', str),
        ('cred_offer', IndyCredOffer),
    )

class IndyCredentialRequest(ServiceResponse):
    """
    The message class representing a successful credential request creation

    Args:
        holder_id (str): the identifier of the holder service
        cred_offer (IndyCredOffer): the credential offer used as a basis
        result (str): the resulting credential request
        metadata (dict): the credential request metadata
    """
    _fields = (
        ('holder_id', str),
        ('cred_offer', IndyCredOffer),
        ('result', str),
        ('metadata', dict),
    )

class IndyCreateCredentialReq(ServiceRequest):
    """
    The message class representing an request to create a credential
    """
    _fields = (
        ('cred_offer', IndyCredOffer),
        ('cred_req_result', str),
        ('cred_req_metadata', dict),
        ('cred_data', dict),
    )


class IndyCredential(ServiceResponse):
    """
    The message class representing a successful credential creation
    """
    _fields = (
        ('issuer_id', str),
        ('schema_name', str),
        ('issuer_did', str),
        ('cred_data', dict),
        ('cred_def', dict),
        ('cred_req_metadata', dict),
        ('cred_revoc_id', str),
    )


class IndyStoreCredentialReq(ServiceRequest):
    """
    The message class representing an request to store a credential
    """
    _fields = (
        ('holder_id', str),
        ('cred', IndyCredential),
    )


class IndyStoredCredential(ServiceResponse):
    """
    The message class representing an successful response to storing a credential
    """
    _fields = (
        ('holder_id', str),
        ('cred', IndyCredential),
        ('result', dict),
    )


class IndyResolveDidReq(ServiceRequest):
    """
    The message class representing a request to resolve a DID
    """
    _fields = (
        ('seed', str),
    )


class IndyResolvedDid(ServiceResponse):
    """
    The message class representing a response to DID resolution request
    """

    _fields = (
        ('seed', str),
        ('did', str),
    )


class IndyRegisterIssuerReq(ServiceRequest):
    """
    The message class representing a request to register an issuer
    """
    _fields = (
        ('config', dict),
    )


class IndyIssuerStatusReq(ServiceRequest):
    """
    The message class representing a request for an issuer status update
    """
    _fields = (
        ('issuer_id', str),
    )


class IndyIssuerStatus(ServiceResponse):
    """
    The message class representing an issuer status update
    """
    _fields = (
        ('issuer_id', str),
        ('status', dict),
    )


class IndyVerifyProofReq(ServiceRequest):
    """
    The message class representing a request to verify a proof
    """
    _fields = (
        ('proof_req', dict),
        ('proof', dict),
    )


class IndyVerifiedProof(ServiceResponse):
    """
    The message class representing a successful proof verification
    """
    _fields = (
        ('verified', str),
        ('parsed_proof', dict),
    )


class WalletConfig:
    """
    Manage configuration settings for an Indy wallet
    """
    def __init__(self, **params):
        self.name = params.get("name")
        if not self.name:
            raise ValueError("Missing wallet name")
        self.seed = params.get("seed")
        if not self.seed:
            raise ValueError("Missing seed for wallet '{}'".format(self.name))
        if len(self.seed) != 32:
            raise ValueError(
                "Wallet seed length is not 32 characters: {}".format(self.seed)
            )
        self.genesis_path = params.get("genesis_path")
        self.type = params.get("type", None)  # or virtual?
        self.params = params.get("params", {})
        if "freshness_time" not in self.params:
            self.params["freshness_time"] = 0
        self.creds = {"key": ""}


class AgentWrapper:
    """
    A wrapper for the :class:`_BaseAgent` instance which handles configuration loading
    and allows the wallet to be kept open between requests
    """

    def __init__(self, wallet_config: WalletConfig, instance_cls,
                 issuer_type: str, ext_cfg=None):
        if not wallet_config.genesis_path:
            raise ValueError("Missing genesis_path for wallet configuration")

        self._pool = NodePool(
            wallet_config.name + "-" + issuer_type, wallet_config.genesis_path
        )

        self._instance_cls = instance_cls
        self._instance = None
        self._wallet = Wallet(
            self._pool,
            wallet_config.seed,
            wallet_config.name + "-" + issuer_type + "-Wallet",
            wallet_config.type,
            wallet_config.params,
            wallet_config.creds,
        )
        self._ext_cfg = ext_cfg
        self._opened = None
        self._keep_open = False

    @property
    def opened(self) -> bool:
        """
        Return current state of the :class:`_BaseAgent` instance
        """
        return self._opened is not None

    @property
    def instance(self):
        """
        Accessor for the opened :class:`_BaseAgent` instance
        """
        return self._instance

    def keep_open(self, flag=True):
        """
        Set the keep-open flag to keep the wallet open between requests
        """
        self._keep_open = flag

    async def open(self, keep_open=True) -> _BaseAgent:
        """
        Open the connection to the transaction pool and wallet
        """
        if keep_open:
            self._keep_open = True
        if self._opened:
            return self._opened
        await self._pool.open()
        self._instance = self._instance_cls(
            await self._wallet.create(), self._ext_cfg
        )
        self._opened = await self._instance.open()
        if isinstance(self._instance, VonHolderProver):
            # NOTE: should only create this once,
            # and only in the root wallet (virtual_wallet == None)
            await self._instance.create_link_secret(str(uuid.uuid4()))
        return self._opened

    async def close(self):
        """
        Close the wallet and transaction pool connections
        """
        if self._opened:
            await self._instance.close()
            await self._pool.close()
        self._opened = None
        self._keep_open = False

    async def __aenter__(self):
        return await self.open(False)

    async def __aexit__(self, exc_type, exc_value, traceback):
        if exc_type is not None:
            LOGGER.exception("Exception in VON %s:", self._wallet.name)
        if not self._keep_open:
            await self.close()


class IndyIssuerConfig:
    """
    Manage configuration settings for an Issuer, including wallet settings
    and schemas bound for the ledger
    """
    def __init__(self, **params):
        self.agent = None
        self.auto_register = params.get("auto_register", True)
        self.did = params.get("did")
        self.endpoint = params.get("endpoint")
        self.ident = params.get("id")
        self.manager_pid = params.get("manager_pid")
        self.registered = False
        self.schemas = []
        self.synced = False
        self.wrapper = None
        wallet_cfg = params.get("wallet") or {}
        if "name" not in wallet_cfg:
            wallet_cfg["name"] = self.ident
        self.wallet_config = WalletConfig(**wallet_cfg)

        schemas = params.get("schemas")
        if schemas:
            for schema in schemas:
                self.add_schema(schema)

    @property
    def extended_config(self):
        """
        Accessor for the extended :class:`Issuer` configuration
        """
        ret = {}
        if self.endpoint:
            ret["endpoint"] = self.endpoint
        return ret

    def add_schema(self, schema: Schema):
        """
        Add a schema to the Issuer definition

        Args:
            schema: the :class:`Schema` to be added
        """
        self.schemas.append({
            "definition": schema.copy(),
            "ledger": None,
            "cred_def": None,
        })

    def get_schema_config(self, match: Schema) -> dict:
        """
        Find the extended information for a specific schema, including the ledger schema
        definition and credential definition (if any)

        Args:
            match: the :class:`Schema` to be located
        """
        for schema in self.schemas:
            defn = schema["definition"]
            if defn.compare(match):
                return schema
        return None

    @property
    def status(self) -> dict:
        """
        Get the current status of the issuer
        """
        return {
            "did": self.did,
            "registered": self.registered,
            "synced": self.synced,
        }


class IndyLedger(ServiceBase):
    """
    A class for managing interactions with the Hyperledger Indy ledger
    """

    def __init__(self, pid: str, exchange: Exchange, env: Mapping, spec: dict = None):
        super(IndyLedger, self).__init__(pid, exchange, env)
        self._config = {}
        self._genesis_path = None
        self._issuers = {}
        self._ledger_url = None
        self._verifier = None
        self._update_config(spec)

    def _update_config(self, spec) -> None:
        """
        Load configuration settings
        """
        if spec:
            self._config.update(spec)
        if "ledger_url" in spec:
            self._ledger_url = spec["ledger_url"]

    async def _service_sync(self) -> bool:
        """
        Perform the initial setup of the ledger connection, including downloading the
        genesis transaction file
        """
        await asyncio.sleep(1)  # avoid odd TimeoutError on genesis txn retrieval
        await self._check_genesis_path()
        synced = True
        for issuer in self._issuers.values():
            if not await self._sync_issuer(issuer):
                synced = False
        return synced

    def _add_issuer(self, **params) -> str:
        """
        Add an issuer configuration

        Args:
            params: parameters to be passed to the :class:`IndyIssuerConfig` constructor
        """
        if "id" not in params:
            raise ValueError("Missing 'id' for issuer")
        cfg = IndyIssuerConfig(**params)
        self._issuers[cfg.ident] = cfg
        return cfg.ident

    def _get_issuer_status(self, issuer_id: str):
        """
        Return the status of a registered issuer to the client

        Args:
            issuer_id: the unique identifier of the issuer
        """
        if issuer_id in self._issuers:
            msg = IndyIssuerStatus(issuer_id, self._issuers[issuer_id].status)
        else:
            msg = IndyLedgerError('Unregistered issuer: {}'.format(issuer_id))
        return msg

    async def _sync_issuer(self, issuer: IndyIssuerConfig) -> bool:
        """
        Perform issuer synchronization, registering the DID and publishing schemas
        and credential definitions as required

        Args:
            issuer: the Indy issuer configuration
        """
        if not issuer.synced:
            if not issuer.wrapper:
                LOGGER.info(
                    "Init Indy issuer %s with seed %s",
                    issuer.ident,
                    issuer.wallet_config.seed,
                )

                issuer.wallet_config.genesis_path = self._genesis_path
                issuer.wrapper = AgentWrapper(
                    issuer.wallet_config,
                    VonIssuer,
                    "Issuer",
                    issuer.extended_config,
                )

            # FIXME - catch sync exceptions here
            if not issuer.agent:
                issuer.agent = await issuer.wrapper.open()
                issuer.did = issuer.agent.did

            if not issuer.registered:
                # check DID is registered
                auto_register = (
                    self._config.get("auto_register", True)
                    and issuer.auto_register
                )
                await self._check_registration(issuer.agent, auto_register)

                # check endpoint is registered (if any)
                # await self._check_endpoint(issuer.agent, issuer.endpoint)
                issuer.registered = True

            # publish schemas
            for schema in issuer.schemas:
                await self._publish_schema(issuer.agent, schema)

            issuer.synced = True
            if issuer.manager_pid:
                self.send_noreply(
                    issuer.manager_pid,
                    IndyIssuerStatus(issuer.ident, issuer.status),
                )

            LOGGER.info("Indy issuer synced: %s", issuer.ident)
        return issuer.synced

    async def _check_genesis_path(self) -> None:
        """
        Make sure that the genesis path is defined, and download the transaction file if needed.
        """
        if not self._genesis_path:
            path = self._config.get("genesis_path")
            if not path:
                raise ValueError("Missing genesis_path")
            genesis_path = pathlib.Path(path)
            if not genesis_path.exists():
                ledger_url = self._ledger_url
                if not ledger_url:
                    raise ValueError(
                        "Cannot retrieve genesis transaction without ledger_url"
                    )
                parent_path = pathlib.Path(genesis_path.parent)
                if not parent_path.exists():
                    parent_path.mkdir(parents=True)
                await self._fetch_genesis_txn(ledger_url, genesis_path)
            elif genesis_path.is_dir():
                raise ValueError("genesis_path must not point to a directory")
            self._genesis_path = path

    async def _fetch_genesis_txn(self, ledger_url: str, target_path: str) -> bool:
        """
        Download the genesis transaction file from the ledger server

        Args:
            ledger_url: the root address of the von-network ledger
            target_path: the filesystem path of the genesis transaction file once downloaded
        """
        LOGGER.info(
            "Fetching genesis transaction file from %s/genesis", ledger_url
        )
        async with aiohttp.ClientSession(read_timeout=30) as client:
            response = await client.get("{}/genesis".format(ledger_url))
        if response.status != 200:
            raise RuntimeError(
                "Error downloading genesis file: status {}".format(
                    response.status
                )
            )
        data = await response.text()

        # check data is valid json
        LOGGER.debug("Genesis transaction response: %s", data)
        lines = data.splitlines()
        if not lines or not json.loads(lines[0]):
            raise RuntimeError("Genesis transaction file is not valid JSON")

        # write result to provided path
        with target_path.open("x") as output_file:
            output_file.write(data)
        return True

    async def _check_registration(self, agent: _BaseAgent, auto_register: bool = True) -> None:
        """
        Look up our nym on the ledger and register it if not present

        Args:
            agent: the initialized and opened agent to be checked
            auto_register: whether to automatically register the DID on the ledger
        """
        did = agent.did
        LOGGER.debug("Checking DID registration %s", did)
        nym_json = await agent.get_nym(did)
        LOGGER.debug("get_nym result for %s: %s", did, nym_json)

        nym_info = json.loads(nym_json)
        if not nym_info:
            if not auto_register:
                raise RuntimeError(
                    "DID is not registered on the ledger and auto-registration disabled"
                )

            ledger_url = self._ledger_url
            if not ledger_url:
                raise ValueError("Cannot register DID without ledger_url")
            LOGGER.info("Registering DID %s", did)

            async with aiohttp.ClientSession(read_timeout=30) as client:
                response = await client.post(
                    "{}/register".format(ledger_url),
                    json={"did": did, "verkey": agent.verkey},
                )
                if response.status != 200:
                    raise RuntimeError(
                        "DID registration failed: {}".format(
                            await response.text()
                        )
                    )
                nym_info = await response.json()
                LOGGER.debug("Registration response: %s", nym_info)
                if not nym_info or not nym_info["did"]:
                    raise RuntimeError(
                        "DID registration failed: {}".format(nym_info)
                    )

    async def _check_endpoint(self, agent: _BaseAgent, endpoint: str) -> None:
        """
        Look up our endpoint on the ledger and register it if not present

        Args:
            agent: the initialized and opened agent to be checked
            endpoint: the endpoint to be added to the ledger, if not defined
        """
        if not endpoint:
            return None
        did = agent.did
        LOGGER.debug("Checking endpoint registration %s", endpoint)
        endp_json = await agent.get_endpoint(did)
        LOGGER.debug("get_endpoint result for %s: %s", did, endp_json)

        endp_info = json.loads(endp_json)
        if not endp_info:
            endp_info = await agent.send_endpoint()
            LOGGER.debug("Endpoint stored: %s", endp_info)

    async def _publish_schema(self, issuer: VonIssuer, schema: dict) -> None:
        """
        Check the ledger for a specific schema and version, and publish it if not found.
        Also publish the related credential definition if not found

        Args:
            issuer: the initialized and opened issuer instance publishing the schema
            schema: a dict which will be updated with the published schema and credential def
        """

        if not schema or "definition" not in schema:
            raise ValueError("Missing schema definition")
        definition = schema["definition"]

        if not schema.get("ledger"):
            LOGGER.info(
                "Checking for schema: %s (%s)",
                definition.name,
                definition.version,
            )
            # Check if schema exists on ledger

            try:
                s_key = schema_key(
                    schema_id(issuer.did, definition.name, definition.version)
                )
                schema_json = await issuer.get_schema(s_key)
                ledger_schema = json.loads(schema_json)
                log_json("Schema found on ledger:", ledger_schema, LOGGER)
            except AbsentSchema:
                # If not found, send the schema to the ledger
                LOGGER.info(
                    "Publishing schema: %s (%s)",
                    definition.name,
                    definition.version,
                )
                schema_json = await issuer.send_schema(
                    json.dumps(
                        {
                            "name": definition.name,
                            "version": definition.version,
                            "attr_names": definition.attr_names,
                        }
                    )
                )
                ledger_schema = json.loads(schema_json)
                if not ledger_schema or not ledger_schema.get("seqNo"):
                    raise RuntimeError("Schema was not published to ledger")
                log_json("Published schema:", ledger_schema, LOGGER)
            schema["ledger"] = ledger_schema

        if not schema.get("credential_definition"):
            # Check if credential definition has been published
            LOGGER.info(
                "Checking for credential def: %s (%s)",
                definition.name,
                definition.version,
            )

            try:
                cred_def_json = await issuer.get_cred_def(
                    cred_def_id(issuer.did, schema["ledger"]["seqNo"])
                )
                cred_def = json.loads(cred_def_json)
                log_json("Credential def found on ledger:", cred_def, LOGGER)
            except AbsentCredDef:
                # If credential definition is not found then publish it
                LOGGER.info(
                    "Publishing credential def: %s (%s)",
                    definition.name,
                    definition.version,
                )
                cred_def_json = await issuer.send_cred_def(
                    schema_json, revocation=False
                )
                cred_def = json.loads(cred_def_json)
                log_json("Published credential def:", cred_def, LOGGER)
            schema["credential_definition"] = cred_def

    async def _handle_create_cred_offer(self, request: IndyCreateCredOfferReq):
        """
        Create a credential offer for TheOrgBook

        Args:
            request: the request for a credential offer
        """
        issuer = self._issuers[request.issuer_id]
        schema = issuer.get_schema_config(request.schema_def)

        LOGGER.info(
            "Creating indy credential offer for issuer %s, schema %s",
            issuer.ident,
            schema["definition"].name,
        )
        cred_offer_json = await issuer.agent.create_cred_offer(
            schema["ledger"]["seqNo"]
        )

        return IndyCredOffer(
            request.issuer_id,
            request.schema_def,
            json.loads(cred_offer_json),
            schema["credential_definition"],
        )

    async def _handle_create_cred(self, request: IndyCreateCredentialReq):
        """
        Create a credential for TheOrgBook

        Args:
            request: the request to store a credential
        """
        offer = request.cred_offer
        issuer = self._issuers[offer.issuer_id]
        schema = issuer.get_schema_config(offer.schema_def)

        (cred_json, cred_revoc_id) = await issuer.agent.create_cred(
            json.dumps(request.cred_offer.offer),
            request.cred_req_result,
            request.cred_data,
        )

        return IndyCredential(
            offer.issuer_id,
            schema["definition"].name,
            issuer.agent.did,
            json.loads(cred_json),
            schema["credential_definition"],
            request.cred_req_metadata,
            cred_revoc_id,
        )

    async def _get_verifier(self) -> AgentWrapper:
        """
        Fetch or create an :class:`AgentWrapper` representing a standard Verifier agent,
        used to verify proofs
        """
        if not self._verifier:
            wallet_cfg = WalletConfig(
                name="GenericVerifier",
                seed="verifier-seed-000000000000000000",
                genesis_path=self._genesis_path,
            )
            self._verifier = AgentWrapper(wallet_cfg, VonVerifier, "Verifier")
            await self._verifier.open()
        return self._verifier.instance

    async def _handle_verify_proof(self, request: IndyVerifyProofReq):
        """
        Verify a proof returned by TheOrgBook

        Args:
            request: the request to verify a proof
        """
        verifier = await self._get_verifier()
        result = await verifier.verify_proof(request.proof_req, request.proof)
        parsed_proof = revealed_attrs(request.proof)

        return IndyVerifiedProof(result, parsed_proof)

    async def _handle_ledger_status(self):
        """
        Download the ledger status from von-network and return it to the client
        """
        url = self._ledger_url
        async with self.http as client:
            response = await client.get("{}/status".format(url))
        return await response.text()

    async def _service_request(self, request: ServiceRequest) -> ServiceResponse:
        """
        Process a message from the exchange and send the reply, if any

        Args:
            message: the message to be processed
        """
        if isinstance(request, IndyLedgerStatusReq):
            reply = await self._handle_ledger_status()

        elif isinstance(request, IndyRegisterIssuerReq):
            try:
                issuer_id = self._add_issuer(**request.config)
                reply = self._get_issuer_status(issuer_id)
                self.run_task(self._sync())
            except ValueError as e:
                reply = IndyLedgerError(str(e))

        elif isinstance(request, IndyIssuerStatusReq):
            reply = self._get_issuer_status(request.issuer_id)

        elif isinstance(request, IndyCreateCredOfferReq):
            reply = await self._handle_create_cred_offer(request)

        elif isinstance(request, IndyCreateCredentialReq):
            reply = await self._handle_create_cred(request)

        elif isinstance(request, IndyVerifyProofReq):
            reply = await self._handle_verify_proof(request)

        elif isinstance(request, IndyResolveDidReq):
            reply = IndyResolvedDid(request.seed, seed_to_did(request.seed))

        else:
            reply = None
        return reply
