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
import random
import string
from typing import Mapping
import uuid

import aiohttp
from didauth.indy import seed_to_did
from von_agent.error import AbsentSchema, AbsentCredDef
from von_agent.nodepool import NodePool
from von_agent.util import cred_def_id, revealed_attrs, schema_id, schema_key

from ..common.service import (
    Exchange,
    ServiceBase,
    ServiceRequest,
    ServiceResponse)
from ..common.util import log_json
from .config import (
    AgentType,
    AgentCfg,
    ConnectionCfg,
    IndyConfigError,
    IssuerTargetCfg,
    SchemaCfg,
    WalletCfg)
from .messages import (
    IndyServiceError,
    LedgerStatusReq,
    LedgerStatus,
    RegisterWalletReq,
    WalletStatusReq,
    WalletStatus,
    RegisterAgentReq,
    AgentStatusReq,
    AgentStatus,
    RegisterIssuerSchemaReq,
    RegisterIssuerCredDefReq,
    RegisterIssuerTargetReq,
    IssuerTargetStatusReq,
    IssuerTargetStatus,
    RegisterConnectionReq,
    ConnectionStatusReq,
    ConnectionStatus)

LOGGER = logging.getLogger(__name__)


def _make_id(pfx: str = '', length=12) -> str:
    return pfx + ''.join(random.choice(string.ascii_letters) for _ in range(length))


class IndyService(ServiceBase):
    """
    A class for managing interactions with the Hyperledger Indy ledger
    """

    def __init__(self, pid: str, exchange: Exchange, env: Mapping, spec: dict = None):
        super(IndyService, self).__init__(pid, exchange, env)
        self._config = {}
        self._genesis_path = None
        self._agents = {}
        self._connections = {}
        self._name = pid
        self._opened = False
        self._pool = None
        self._targets = {}
        self._wallets = {}
        self._ledger_url = None
        self._verifier = None
        self._update_config(spec)

    def _update_config(self, spec) -> None:
        """
        Load configuration settings
        """
        if spec:
            self._config.update(spec)
        if "name" in spec:
            self._name = spec["name"]
        if "ledger_url" in spec:
            self._ledger_url = spec["ledger_url"]

    async def _service_sync(self) -> bool:
        """
        Perform the initial setup of the ledger connection, including downloading the
        genesis transaction file
        """
        await self._setup_pool()
        synced = True
        for wallet in self._wallets.values():
            if not wallet.created:
                await wallet.create(self._pool)
        for agent in self._agents.values():
            if not await self._sync_agent(agent):
                synced = False
        for target in self._targets.values():
            if not await self._sync_target(target):
                synced = False
        for connection in self._connections.values():
            if not await self._sync_connection(connection):
                synced = False
        return synced

    def _add_agent(self, agent_type: str, wallet_id: str, **params) -> str:
        """
        Add an agent configuration

        Args:
            params: parameters to be passed to the :class:`AgentCfg` constructor
        """
        if wallet_id not in self._wallets:
            raise KeyError("Wallet ID not registered: {}".format(wallet_id))
        cfg = AgentCfg(agent_type, wallet_id, **params)
        if not cfg.agent_id:
            cfg.agent_id = _make_id("agent-")
        if cfg.agent_id in self._agents:
            raise KeyError("Duplicate agent ID: {}".format(cfg.agent_id))
        self._agents[cfg.agent_id] = cfg
        return cfg.agent_id

    def _get_agent_status(self, agent_id: str) -> ServiceResponse:
        """
        Return the status of a registered agent

        Args:
            agent_id: the unique identifier of the agent
        """
        if agent_id in self._agents:
            msg = AgentStatus(agent_id, self._agents[agent_id].status)
        else:
            msg = IndyServiceError("Unregistered agent: {}".format(agent_id))
        return msg

    def _add_connection(self, issuer_id: str, target_id: str, **params) -> str:
        """
        Add a connection configuration

        Args:
            issuer_id: the identifier of the registered issuer
            target_id: the identifier of the registered issuer target
            params: parameters to be passed to the :class:`ConnectionCfg` constructor
        """
        if issuer_id not in self._agents:
            raise KeyError("Issuer ID not registered: {}".format(issuer_id))
        if target_id not in self._targets:
            raise KeyError("Target ID not registered: {}".format(target_id))
        cfg = ConnectionCfg(issuer_id, target_id, **params)
        if not cfg.connection_id:
            cfg.connection_id = _make_id("connection-")
        if cfg.connection_id in self._connections:
            raise KeyError("Duplicate connection ID: {}".format(cfg.connection_id))
        self._connections[cfg.connection_id] = cfg
        return cfg.connection_id

    def _get_connection_status(self, connection_id: str) -> ServiceResponse:
        """
        Return the status of a registered connection

        Args:
            connection_id: the unique identifier of the connection
        """
        if connection_id in self._connections:
            msg = ConnectionStatus(connection_id, self._connections[connection_id].status)
        else:
            msg = IndyServiceError("Unregistered connection: {}".format(connection_id))
        return msg

    def _add_target(self, target_type: str, **params) -> str:
        """
        Add an issuer target configuration

        Args:
            target_type: the type of the issuer target (TheOrgBook / von-x)
            params: parameters to be passed to the :class:`IssuerTargetCfg` constructor
        """
        cfg = IssuerTargetCfg(target_type, **params)
        if not cfg.target_id:
            cfg.target_id = _make_id("target-")
        if cfg.target_id in self._targets:
            raise KeyError("Duplicate target ID: {}".format(cfg.target_id))
        self._targets[cfg.target_id] = cfg
        return cfg.target_id

    def _get_target_status(self, target_id: str) -> ServiceResponse:
        """
        Return the status of a registered target

        Args:
            target_id: the unique identifier of the target
        """
        if target_id in self._targets:
            msg = IssuerTargetStatus(target_id, self._targets[target_id].status)
        else:
            msg = IndyServiceError("Unregistered target: {}".format(target_id))
        return msg

    def _add_wallet(self, **params) -> str:
        """
        Add a wallet configuration

        Args:
            params: parameters to be passed to the :class:`WalletCfg` constructor
        """
        cfg = WalletCfg(**params)
        if not cfg.wallet_id:
            cfg.wallet_id = _make_id("wallet-")
        if cfg.wallet_id in self._wallets:
            raise KeyError("Duplicate wallet ID: {}".format(cfg.wallet_id))
        self._wallets[cfg.wallet_id] = cfg
        return cfg.wallet_id

    def _get_wallet_status(self, wallet_id: str) -> ServiceResponse:
        """
        Return the status of a registered wallet

        Args:
            wallet_id: the unique identifier of the wallet
        """
        if wallet_id in self._wallets:
            msg = WalletStatus(wallet_id, self._wallets[wallet_id].status)
        else:
            msg = IndyServiceError("Unregistered wallet: {}".format(wallet_id))
        return msg

    async def _sync_agent(self, agent: AgentCfg) -> bool:
        """
        Perform agent synchronization, registering the DID and publishing schemas
        and credential definitions as required

        Args:
            agent: the Indy agent configuration
        """
        if not agent.synced:
            if not agent.created:
                wallet = self._wallets[agent.wallet_id]
                if not wallet.created:
                    return False
                await agent.create(wallet)

            #if not agent.opened:
            #    await agent.open()

            if not agent.registered:
                # check DID is registered
                auto_register = self._config.get("auto_register", True)
                await self._check_registration(agent, auto_register, agent.role)

                # check endpoint is registered (if any)
                # await self._check_endpoint(agent.instance, agent.endpoint)
                agent.registered = True

            # publish schemas
            for schema in agent.schemas:
                await self._publish_schema(agent, schema)

            agent.synced = True
            LOGGER.info("Indy agent synced: %s", agent.agent_id)
        return agent.synced

    async def _sync_target(self, target: IssuerTargetCfg) -> bool:
        if not target.created:
            await target.create()
        return target.created

    async def _sync_connection(self, connection: ConnectionCfg) -> bool:
        issuer = self._agents[connection.issuer_id]
        target = self._targets[connection.target_id]

        if not connection.created:
            if issuer.synced and target.created:
                http_client = self._issuer_http_client(issuer.agent_id)
                await connection.create(target, http_client)

        if not connection.synced:
            await connection.sync(issuer, target)
        return connection.synced

    async def _setup_pool(self) -> None:
        if not self._opened:
            await asyncio.sleep(1)  # help avoid odd TimeoutError on genesis txn retrieval
            await self._check_genesis_path()
            self._pool = NodePool(self._name, self._genesis_path)
            await self._pool.open()
            self._opened = True

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

        try:
            async with aiohttp.ClientSession(read_timeout=30) as client:
                response = await client.get("{}/genesis".format(ledger_url))
        except aiohttp.ClientError as e:
            raise ServiceSyncError("Error downloading genesis transaction file: {}".format(str(e)))

        if response.status != 200:
            raise RuntimeError(
                "Error downloading genesis file: status {}".format(
                    response.status
                )
            )

        # check data is valid json
        data = await response.text()
        LOGGER.debug("Genesis transaction response: %s", data)
        lines = data.splitlines()
        if not lines or not json.loads(lines[0]):
            raise RuntimeError("Genesis transaction file is not valid JSON")

        # write result to provided path
        with target_path.open("x") as output_file:
            output_file.write(data)
        return True

    async def _check_registration(self, agent: AgentCfg, auto_register: bool = True,
                                  role: str = "") -> None:
        """
        Look up our nym on the ledger and register it if not present

        Args:
            agent: the initialized and opened agent to be checked
            auto_register: whether to automatically register the DID on the ledger
        """
        did = agent.did
        LOGGER.debug("Checking DID registration %s", did)
        nym_json = await agent.instance.get_nym(did)
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
                    json={"did": did, "verkey": agent.verkey, "role": role},
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

    async def _check_endpoint(self, agent: AgentCfg, endpoint: str) -> None:
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
        endp_json = await agent.instance.get_endpoint(did)
        LOGGER.debug("get_endpoint result for %s: %s", did, endp_json)

        endp_info = json.loads(endp_json)
        if not endp_info:
            endp_info = await agent.instance.send_endpoint()
            LOGGER.debug("Endpoint stored: %s", endp_info)

    async def _publish_schema(self, issuer: AgentCfg, schema: dict) -> None:
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
                schema_json = await issuer.instance.get_schema(s_key)
                ledger_schema = json.loads(schema_json)
                log_json("Schema found on ledger:", ledger_schema, LOGGER)
            except AbsentSchema:
                # If not found, send the schema to the ledger
                LOGGER.info(
                    "Publishing schema: %s (%s)",
                    definition.name,
                    definition.version,
                )
                schema_json = await issuer.instance.send_schema(
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
                cred_def_json = await issuer.instance.get_cred_def(
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
                cred_def_json = await issuer.instance.send_cred_def(
                    schema_json, revocation=False
                )
                cred_def = json.loads(cred_def_json)
                log_json("Published credential def:", cred_def, LOGGER)
            schema["credential_definition"] = cred_def

    async def _handle_create_cred_offer(self, request):
        """
        Create a credential offer for TheOrgBook

        Args:
            request: the request for a credential offer
        """
        issuer = self._agents[request.issuer_id]
        schema = issuer.get_schema_config(request.schema_name, request.schema_version)

        LOGGER.info(
            "Creating indy credential offer for issuer %s, schema %s",
            issuer.agent_id,
            schema["definition"].name,
        )
        cred_offer_json = await issuer.instance.create_cred_offer(
            schema["ledger"]["seqNo"]
        )

        return IndyCredOffer(
            request.issuer_id,
            request.schema_def,
            json.loads(cred_offer_json),
            schema["credential_definition"],
        )

    async def _handle_create_cred(self, request):
        """
        Create a credential for TheOrgBook

        Args:
            request: the request to store a credential
        """
        offer = request.cred_offer
        issuer = self._agents[offer.issuer_id]
        schema = issuer.get_schema_config(offer.schema_def)

        (cred_json, cred_revoc_id) = await issuer.instance.create_cred(
            json.dumps(request.cred_offer.offer),
            request.cred_req_result,
            request.cred_data,
        )

        return IndyCredential(
            offer.issuer_id,
            schema["definition"].name,
            issuer.did,
            json.loads(cred_json),
            schema["credential_definition"],
            request.cred_req_metadata,
            cred_revoc_id,
        )

    async def _get_verifier(self) -> AgentCfg:
        """
        Fetch or create an :class:`AgentWrapper` representing a standard Verifier agent,
        used to verify proofs
        """
        if not self._verifier:
            wallet_cfg = self._wallets['_verifier'] = WalletCfg(
                name="GenericVerifier",
                seed="verifier-seed-000000000000000000",
            )
            await wallet_cfg.create(self._pool)
            self._verifier = AgentCfg(AgentType.verifier, '_verifier')
            await self._verifier.create(wallet_cfg)
        return self._verifier

    async def _handle_verify_proof(self, request):
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

    def _agent_http_client(self, agent_id: str = None, **kwargs):
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
        return super(IndyService, self).http_client(**kwargs)

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
            secret = agent.wallet_seed
            if isinstance(secret, str):
                secret = secret.encode("ascii")
            return SignedRequestAuth(key_id, "ed25519", secret, header_list)
        return None

    async def _service_request(self, request: ServiceRequest) -> ServiceResponse:
        """
        Process a message from the exchange and send the reply, if any

        Args:
            message: the message to be processed
        """
        if isinstance(request, LedgerStatusReq):
            text = await self._handle_ledger_status()
            reply = LedgerStatus(text)

        elif isinstance(request, RegisterAgentReq):
            try:
                agent_id = self._add_agent(request.agent_type, request.wallet_id, **request.config)
                reply = self._get_agent_status(agent_id)
                self.run_task(self._sync())
            except IndyConfigError as e:
                reply = IndyServiceError(str(e))

        elif isinstance(request, RegisterConnectionReq):
            try:
                connection_id = self._add_connection(
                    request.issuer_id, request.target_id, **request.config)
                reply = self._get_connection_status(connection_id)
                self.run_task(self._sync())
            except IndyConfigError as e:
                reply = IndyServiceError(str(e))

        elif isinstance(request, RegisterIssuerTargetReq):
            try:
                target_id = self._add_target(request.target_type, **request.config)
                reply = self._get_target_status(target_id)
                self.run_task(self._sync())
            except IndyConfigError as e:
                reply = IndyServiceError(str(e))

        elif isinstance(request, RegisterWalletReq):
            try:
                wallet_id = self._add_wallet(**request.config)
                reply = self._get_wallet_status(wallet_id)
                self.run_task(self._sync())
            except IndyConfigError as e:
                reply = IndyServiceError(str(e))

        elif isinstance(request, AgentStatusReq):
            reply = self._get_agent_status(request.agent_id)

        elif isinstance(request, ConnectionStatusReq):
            reply = self._get_connection_status(request.connection_id)

        elif isinstance(request, IssuerTargetStatusReq):
            reply = self._get_target_status(request.target_id)

        elif isinstance(request, WalletStatusReq):
            reply = self._get_wallet_status(request.wallet_id)

        #elif isinstance(request, IndyVerifyProofReq):
        #    reply = await self._handle_verify_proof(request)

        else:
            reply = None
        return reply
