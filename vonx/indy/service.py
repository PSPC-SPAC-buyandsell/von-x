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
The Indy service implements handlers for all the ledger-related messages, sychronizes
agents and connections, and handles the core logic for working with credentials and proofs.
"""

import asyncio
import base64
import json
import hashlib
import logging
import pathlib
import random
import string
import time
from typing import Mapping, Sequence

from didauth.ext.aiohttp import SignedRequest, SignedRequestAuth
from von_anchor.error import AbsentCred, AbsentSchema, AbsentCredDef
from von_anchor.nodepool import NodePool
from von_anchor.util import cred_def_id, revealed_attrs, schema_id, schema_key, \
    proof_req_infos2briefs, proof_req_briefs2req_creds

from ..common.service import (
    Exchange,
    ServiceBase,
    ServiceRequest,
    ServiceResponse,
    ServiceSyncError,
)
from ..common.util import log_json
from .config import (
    AgentType,
    AgentCfg,
    ConnectionCfg,
    ProofSpecCfg,
    SchemaCfg,
    WalletCfg,
)
from .connection import HttpSession
from .errors import IndyConfigError, IndyConnectionError, IndyError
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
    GenerateCredentialRequestReq,
    StoreCredentialReq,
    ResolveSchemaReq,
    ResolvedSchema,
    ProofRequest,
    ConstructProofReq,
    ConstructedProof,
    RegisterProofSpecReq,
    ProofSpecStatus,
    GenerateProofRequestReq,
    RequestProofReq,
    VerifiedProof,
    VerifyProofReq,
    ResolveNymReq,
    ResolvedNym,
)

LOGGER = logging.getLogger(__name__)


def _make_id(pfx: str = '', length=12) -> str:
    return pfx + ''.join(random.choice(string.ascii_letters) for _ in range(length))


def _prepare_proof_request(spec: ProofSpecCfg, wql_filters: dict = None) -> ProofRequest:
    """
    Prepare the JSON payload for a proof request

    Args:
        spec: the proof request specification
        wql_filters: a dict of WQL filters for the wallet
    """
    req_attrs = {}
    req_preds = {}
    for schema in spec.schemas:
        s_id = schema["definition"].schema_id
        s_uniq = hashlib.sha1(s_id.encode('ascii')).hexdigest()
        for attr in schema["attributes"]:
            req_attrs["{}_{}_uuid".format(s_uniq, attr)] = {
                "name": attr,
                "restrictions": [{
                    "schema_id": s_id,
                }]
            }
        for pred in schema.get("predicates") or []:
            req_preds["{}_{}_uuid".format(s_uniq, pred["name"])] = {
                "name": pred["name"],
                "p_type": pred["p_type"],
                "p_value": pred["p_value"],
                "restrictions": [{
                    "schema_id": s_id,
                }]
            }
    return ProofRequest({
        "name": spec.spec_id,
        "nonce": str(random.randint(10000000000, 100000000000)),  # FIXME - how best to generate?
        "version": spec.version,
        "requested_attributes": req_attrs,
        "requested_predicates": req_preds,
    }, wql_filters)


def _populate_cred_def_ids(proof_req: dict, creds: list):
    """
    Populate cred_def_id for each attribute in proof request if not defined
    """
    cdef_map = {}
    default_cred_def_id = None
    for cred in creds:
        # accept list of cred info or cred briefs
        if "cred_info" in cred:
            cred = cred["cred_info"]
        cdef_map[cred["schema_id"]] = cred["cred_def_id"]
        if len(creds) == 1:
            default_cred_def_id = cred["cred_def_id"]
    for attr in proof_req["requested_attributes"].values():
        attr_cdef_id = None
        attr_schema_id = None
        for rest in attr["restrictions"]:
            attr_cdef_id = rest.get("cred_def_id", attr_cdef_id)
            attr_schema_id = rest.get("schema_id", attr_schema_id)
        if not attr_cdef_id:
            if attr_schema_id and attr_schema_id in cdef_map:
                attr["restrictions"].append({
                    "cred_def_id": cdef_map[attr_schema_id],
                })
            elif default_cred_def_id:
                attr["restrictions"].append({
                    "cred_def_id": default_cred_def_id,
                })
        if "non_revoked" not in attr:
            attr["non_revoked"] = {}


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
        self._ledger_url = None
        self._genesis_url = None
        self._protocol_version = None
        self._max_concurrent_storage = env.get("MAX_CONCURRENT_STORAGE", 20)
        self._name = pid
        self._opened = False
        self._pool = None
        self._proof_specs = {}
        self._storage_lock = None
        self._wallets = {}
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
        if "genesis_url" in spec:
            self._genesis_url = spec["genesis_url"]
        if "protocol_version" in spec:
            self._protocol_version = spec["protocol_version"]

    async def _service_start(self) -> bool:
        """
        Initial service startup sequence
        """
        self._storage_lock = asyncio.Semaphore(self._max_concurrent_storage)
        LOGGER.info("Max concurrent: %s", self._max_concurrent_storage)
        return await super(IndyService, self)._service_start()

    async def _service_sync(self) -> bool:
        """
        Perform the initial setup of the ledger connection, including downloading the
        genesis transaction file
        """
        await self._setup_pool()
        synced = True
        for wallet in self._wallets.values():
            if not wallet.created:
                await wallet.create()
        for agent in self._agents.values():
            if not await self._sync_agent(agent):
                LOGGER.debug("Agent not yet synced: %s", agent.agent_id)
                synced = False
        for connection in self._connections.values():
            if not await self._sync_connection(connection):
                LOGGER.debug("Connection not yet synced: %s", connection.connection_id)
                synced = False
        for spec in self._proof_specs.values():
            if not await self._sync_proof_spec(spec):
                LOGGER.debug("Proof spec not synced: %s", spec.spec_id)
                synced = False
        return synced

    async def _service_stop(self) -> None:
        """
        Shut down active connections
        """
        for connection in self._connections.values():
            await connection.close()
        for agent in self._agents.values():
            await agent.close()
        for wallet in self._wallets.values():
            await wallet.close()

    def _add_agent(self, agent_type: str, wallet_id: str, **params) -> str:
        """
        Add an agent configuration

        Args:
            agent_type: the agent type, issuer or holder
            wallet_id: the identifier for a previously-registered wallet
            params: parameters to be passed to the :class:`AgentCfg` constructor
        """
        if wallet_id not in self._wallets:
            raise IndyConfigError("Wallet ID not registered: {}".format(wallet_id))
        cfg = AgentCfg(agent_type, wallet_id, **params)
        if not cfg.agent_id:
            cfg.agent_id = _make_id("agent-")
        if cfg.agent_id in self._agents:
            raise IndyConfigError("Duplicate agent ID: {}".format(cfg.agent_id))
        agents = self._agents.copy()
        agents[cfg.agent_id] = cfg
        self._agents = agents
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
            msg = IndyServiceFail("Unregistered agent: {}".format(agent_id))
        return msg

    def _add_credential_type(self, issuer_id: str, schema_name: str,
                             schema_version: str, origin_did: str,
                             attr_names: Sequence, config: Mapping = None) -> None:
        """
        Add a credential type to a given issuer

        Args:
            issuer_id: the identifier of the issuer service
            schema_name: the name of the schema used by the credential type
            schema_version: the version of the schema used by the credential type
            origin_did: the DID of the service issuing the schema (optional)
            attr_names: a list of schema attribute names
            config: additional configuration for the credential type
        """
        agent = self._agents[issuer_id]
        if not agent:
            raise IndyConfigError("Agent ID not registered: {}".format(issuer_id))
        schema = SchemaCfg(schema_name, schema_version, attr_names, origin_did)
        agent.add_credential_type(schema, **(config or {}))

    def _add_connection(self, connection_type: str, agent_id: str, **params) -> str:
        """
        Add a connection configuration

        Args:
            connection_type: the type of the connection, normally TheOrgBook
            agent_id: the identifier of the registered agent
            params: parameters to be passed to the :class:`ConnectionCfg` constructor
        """
        if agent_id not in self._agents:
            raise IndyConfigError("Agent ID not registered: {}".format(agent_id))
        cfg = ConnectionCfg(
            connection_type, agent_id, self._agents[agent_id].agent_type.value, **params)
        if not cfg.connection_id:
            cfg.connection_id = _make_id("connection-")
        if cfg.connection_id in self._connections:
            raise IndyConfigError("Duplicate connection ID: {}".format(cfg.connection_id))
        conns = self._connections.copy()
        conns[cfg.connection_id] = cfg
        self._connections = conns
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
            msg = IndyServiceFail("Unregistered connection: {}".format(connection_id))
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
            raise IndyConfigError("Duplicate wallet ID: {}".format(cfg.wallet_id))
        wallets = self._wallets.copy()
        wallets[cfg.wallet_id] = cfg
        self._wallets = wallets
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
            msg = IndyServiceFail("Unregistered wallet: {}".format(wallet_id))
        return msg

    async def _sync_agent(self, agent: AgentCfg) -> bool:
        """
        Perform agent synchronization, registering the DID and publishing schemas
        and credential definitions as required

        Args:
            agent: the Indy agent configuration
        """
        LOGGER.debug('Checking if agent synced...')
        if not agent.synced:
            LOGGER.debug('Syncing agent...')
            if not agent.created:
                LOGGER.debug('Creating agent...')
                wallet = self._wallets[agent.wallet_id]
                if not wallet.created:
                    return False
                await agent.create(wallet, self._pool)

            LOGGER.debug('Opening agent...')
            await agent.open()

            LOGGER.debug('Checking if agent is registered...')
            if not agent.registered:
                # check DID is registered
                LOGGER.debug('Registering agent...')
                auto_register = self._config.get("auto_register", True)
                await self._check_registration(agent, auto_register, agent.role)

                # check endpoint is registered (if any)
                LOGGER.debug('Checking agent endpoint...')
                await self._check_endpoint(agent)
                agent.registered = True

            # publish schemas
            for cred_type in agent.cred_types:
                LOGGER.debug('Publishing agent schemas...')
                await self._publish_schema(agent, cred_type)

            agent.synced = True
            LOGGER.info("Indy agent synced: %s", agent.agent_id)
        return agent.synced

    async def _sync_connection(self, connection: ConnectionCfg) -> bool:
        """
        Perform synchronization on a connection object
        """
        agent = self._agents[connection.agent_id]

        if not connection.synced:
            if not connection.created:
                if not agent.synced:
                    return False
                agent_cfg = agent.get_connection_params(connection)
                if not agent_cfg:
                    agent_cfg = {}
                agent_cfg["config_root"] = self._env.get("CONFIG_ROOT")
                await connection.create(agent_cfg)

            try:
                if not connection.opened:
                    await connection.open(self)

                await connection.sync()
            except IndyConnectionError as e:
                raise ServiceSyncError("Error syncing connection {}: {}".format(
                    connection.connection_id, str(e))) from None
        return connection.synced

    async def _setup_pool(self) -> None:
        """
        Initialize the Indy NodePool, fetching the genesis transaction if necessary
        """
        if not self._opened:
            await self._check_genesis_path()
            if self._protocol_version:
                pool_cfg = {'protocol': self._protocol_version}
            else:
                pool_cfg = None
            self._pool = NodePool(self._name, self._genesis_path, pool_cfg)
            await self._pool.open()
            self._opened = True

    async def _check_genesis_path(self) -> None:
        """
        Make sure that the genesis path is defined, and download the transaction file if needed.
        """
        if not self._genesis_path:
            path = self._config.get("genesis_path")
            if not path:
                raise IndyConfigError("Missing genesis_path")
            genesis_path = pathlib.Path(path)
            if not genesis_path.exists():
                genesis_url = self._genesis_url
                if not genesis_url:
                    ledger_url = self._ledger_url
                    if not ledger_url:
                        raise IndyConfigError(
                            "Cannot retrieve genesis transaction without ledger_url or genesis_url"
                        )
                    genesis_url = "{}/genesis".format(ledger_url)
                parent_path = pathlib.Path(genesis_path.parent)
                if not parent_path.exists():
                    parent_path.mkdir(parents=True)
                await self._fetch_genesis_txn(genesis_url, genesis_path)
            elif genesis_path.is_dir():
                raise IndyConfigError("genesis_path must not point to a directory")
            self._genesis_path = path

    async def _fetch_genesis_txn(self, genesis_url: str, target_path: str) -> bool:
        """
        Download the genesis transaction file from the ledger server

        Args:
            genesis_url: the root address of genesis file
            target_path: the filesystem path of the genesis transaction file once downloaded
        """
        LOGGER.info(
            "Fetching genesis transaction file from %s", genesis_url
        )

        try:
            async with HttpSession('fetching genesis transaction', timeout=15) as handler:
                response = await handler.client.get(genesis_url)
                await handler.check_status(response, (200,))
                data = await response.text()
        except IndyConnectionError as e:
            raise ServiceSyncError(str(e)) from None

        # check data is valid json
        LOGGER.debug("Genesis transaction response: %s", data)
        lines = data.splitlines()
        if not lines or not json.loads(lines[0]):
            raise ServiceSyncError("Genesis transaction file is not valid JSON")

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
                raise ServiceSyncError(
                    "DID is not registered on the ledger and auto-registration disabled"
                )

            ledger_url = self._ledger_url
            if not ledger_url:
                raise IndyConfigError("Cannot register DID without ledger_url")
            LOGGER.info("Registering DID %s", did)

            try:
                async with HttpSession('DID registration', timeout=30) as handler:
                    response = await handler.client.post(
                        "{}/register".format(ledger_url),
                        json={"did": did, "verkey": agent.verkey, "role": role},
                    )
                    await handler.check_status(response, (200,))
                    nym_info = await response.json()
            except IndyConnectionError as e:
                raise ServiceSyncError(str(e)) from None
            LOGGER.debug("Registration response: %s", nym_info)
            if not nym_info or not nym_info["did"]:
                raise ServiceSyncError(
                    "DID registration failed: {}".format(nym_info)
                )

    async def _check_endpoint(self, agent: AgentCfg) -> None:
        """
        Look up our endpoint on the ledger and register it if not present

        Args:
            agent: the initialized and opened agent to be checked
            endpoint: the endpoint to be added to the ledger, if not defined
        """
        await agent.send_endpoint()
        LOGGER.info("Endpoint stored: %s", agent.endpoint)

    async def _publish_schema(self, issuer: AgentCfg, cred_type: dict) -> None:
        """
        Check the ledger for a specific schema and version, and publish it if not found.
        Also publish the related credential definition if not found

        Args:
            issuer: the initialized and opened issuer instance publishing the schema
            cred_type: a dict which will be updated with the published schema and credential def
        """

        if not cred_type or "definition" not in cred_type:
            raise IndyConfigError("Missing schema definition")
        definition = cred_type["definition"]
        s_id = schema_id(issuer.did, definition.name, definition.version)

        if not cred_type.get("ledger_schema"):
            LOGGER.info(
                "Checking for schema: %s (%s)",
                definition.name,
                definition.version,
            )
            # Check if schema exists on ledger

            try:
                s_key = schema_key(s_id)
                schema_json = await issuer.instance.get_schema(s_key)
                ledger_schema = json.loads(schema_json)
                log_json("Schema found on ledger:", ledger_schema, LOGGER)
                if sorted(ledger_schema["attrNames"]) != sorted(definition.attr_names):
                    raise IndyConfigError(
                        "Ledger schema attributes do not match definition, found: {}".format(
                            ledger_schema["attrNames"]))
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
                    raise ServiceSyncError("Schema was not published to ledger")
                log_json("Published schema:", ledger_schema, LOGGER)
            cred_type["ledger_schema"] = ledger_schema

        if not cred_type.get("cred_def"):
            # Check if credential definition has been published
            LOGGER.info(
                "Checking for credential def: %s (%s)",
                definition.name,
                definition.version,
            )

            try:
                cred_def_json = await issuer.instance.get_cred_def(
                    cred_def_id(issuer.did, cred_type["ledger_schema"]["seqNo"], self._pool.protocol)
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
                    s_id, revocation=False
                )
                cred_def = json.loads(cred_def_json)
                log_json("Published credential def:", cred_def, LOGGER)
            cred_type["cred_def"] = cred_def

    async def _issue_credential(self, connection_id: str, schema_name: str,
                                schema_version: str, origin_did: str,
                                cred_data: Mapping,
                                batch: bool = False) -> ServiceResponse:
        """
        Issue a credential to the connection target

        Args:
            connection_id: the identifier of the registered connection
            schema_name: the name of the credential schema
            schema_version: the version of the credential schema
            origin_did: the origin DID of the ledger schema (may be None)
            cred_data: the raw credential attributes
        """
        conn = self._connections.get(connection_id)
        if not conn:
            raise IndyConfigError("Unknown connection id: {}".format(connection_id))
        if not conn.synced:
            raise IndyConfigError("Connection is not yet synchronized: {}".format(connection_id))
        issuer = self._agents[conn.agent_id]
        if not issuer.is_issuer:
            raise IndyConfigError(
                "Cannot issue credential from non-issuer agent: {}".format(issuer.agent_id))
        if not issuer.synced:
            raise IndyConfigError("Issuer is not yet synchronized: {}".format(issuer.agent_id))
        cred_type = issuer.find_credential_type(schema_name, schema_version, origin_did)
        if not cred_type:
            raise IndyConfigError("Could not locate credential type: {}/{} {}".format(
                schema_name, schema_version, origin_did))

        cred_request_cache = cred_type.get("cred_request_cache")
        if not cred_request_cache:
            cred_request_cache = cred_type["cred_request_cache"] = \
                {"request": None, "lock": asyncio.Lock()}
        async with cred_request_cache["lock"]:
            if cred_request_cache["request"] and cred_request_cache["expiry"] > time.time():
                cred_request = cred_request_cache["request"]
                LOGGER.debug("Fetched credential request from cache")
            else:
                cred_offer = await self._create_cred_offer(issuer, cred_type)
                log_json("Created cred offer:", cred_offer, LOGGER)
                cred_request = await conn.instance.generate_credential_request(cred_offer)
                cred_request_cache["request"] = cred_request
                cred_request_cache["expiry"] = time.time() + 600
                LOGGER.debug("Saved cred request cache")
        log_json("Got cred request:", cred_request, LOGGER)

        async def make_cred(cred_data):
            fixed_data = self._fix_cred_data(cred_type["definition"], cred_data)
            cred = await self._create_cred(issuer, cred_request, fixed_data)
            log_json("Created cred:", cred, LOGGER)
            return cred

        if batch:
            creds = []
            for data in cred_data:
                creds.append(asyncio.ensure_future(make_cred(data)))
            creds = await asyncio.gather(*creds)
            stored = await conn.instance.store_credential_batch(creds)
            log_json("Stored credentials:", stored, LOGGER)
        else:
            cred = await make_cred(cred_data)
            stored = await conn.instance.store_credential(cred)
            log_json("Stored credential:", stored, LOGGER)

        return stored

    def _fix_cred_data(self, schema, cred_data: dict):
        """
        Provide empty values for any missing schema attributes and remove unknown
        attributes from the credential data

        Args:
            schema: the schema definition
            cred_data: the dictionary of schema attributes
        """
        ret = {}
        for key in schema.attr_names:
            ret[key] = cred_data.get(key)
        return ret

    async def _create_cred_offer(self, issuer: AgentCfg,
                                 cred_type) -> CredentialOffer:
        """
        Create a credential offer for a specific connection from a given issuer

        Args:
            issuer: the issuer configuration object
            cred_type: the credential type definition
        """
        schema = cred_type["definition"]

        LOGGER.info(
            "Creating Indy credential offer for issuer %s, schema %s",
            issuer.agent_id,
            schema.name,
        )
        cred_offer_json = await issuer.instance.create_cred_offer(
            cred_type["ledger_schema"]["seqNo"]
        )
        return CredentialOffer(
            json.loads(cred_offer_json),
            cred_type["cred_def"]["id"],
        )

    async def _create_cred(self, issuer: AgentCfg, request: CredentialRequest,
                           cred_data: Mapping) -> Credential:
        """
        Create a credential from a credential request for a specific issuer

        Args:
            issuer: the issuer configuration object
            request: a credential request returned from the holder service
            cred_data: the raw credential attributes
        """
        async with self._storage_lock:
            (cred_json, cred_revoc_id, _epoch_creation) = await issuer.instance.create_cred(
                json.dumps(request.cred_offer.data),
                request.data,
                cred_data,
            )
        return Credential(
            json.loads(cred_json),
            request.metadata,
            cred_revoc_id,
        )

    async def _generate_credential_request(
            self, holder_id: str, cred_offer: CredentialOffer) -> CredentialRequest:
        """
        Generate a credential request for a given holder agent from a credential offer
        """
        holder = self._agents.get(holder_id)
        if not holder:
            raise IndyConfigError("Unknown holder id: {}".format(holder_id))
        if not holder.is_holder:
            raise IndyConfigError(
                "Cannot generate credential request from non-holder agent: {}".format(holder.agent_id))
        async with self._storage_lock:
            if not holder.synced:
                raise IndyConfigError("Holder is not yet synchronized: {}".format(holder_id))
            (cred_req, req_metadata_json) = await holder.instance.create_cred_req(
                json.dumps(cred_offer.data),
                cred_offer.cred_def_id,
            )
        return CredentialRequest(
            cred_offer,
            cred_req,
            json.loads(req_metadata_json),
        )

    async def _store_credential(self, holder_id: str,
                                credential: Credential) -> StoredCredential:
        """
        Store a credential in a given holder agent's wallet
        """
        holder = self._agents.get(holder_id)
        if not holder:
            raise IndyConfigError("Unknown holder id: {}".format(holder_id))
        if not holder.is_holder:
            raise IndyConfigError(
                "Cannot store credential using non-holder agent: {}".format(holder.agent_id))
        async with self._storage_lock:
            if not holder.synced:
                raise IndyConfigError("Holder is not yet synchronized: {}".format(holder_id))
            cred_id = await holder.instance.store_cred(
                json.dumps(credential.cred_data),
                json.dumps(credential.cred_req_metadata),
            )
        return StoredCredential(
            credential,
            cred_id,
        )

    async def _resolve_schema(self, schema_name: str, schema_version: str,
                              origin_did: str) -> ResolvedSchema:
        """
        Resolve a schema defined by one of our issuers
        """
        lookup_agent = None
        for agent_id, agent in self._agents.items():
            if agent.synced:
                found = agent.find_credential_type(schema_name, schema_version, origin_did)
                if found:
                    defn = found["definition"]
                    did = defn.origin_did or agent.did
                    return ResolvedSchema(
                        agent_id,
                        schema_id(did, defn.name, defn.version),
                        defn.name,
                        defn.version,
                        did,
                        defn.attr_names,
                    )
                lookup_agent = agent
        if schema_name and schema_version and origin_did and lookup_agent:
            s_id = schema_id(origin_did, schema_name, schema_version)
            s_key = schema_key(s_id)
            try:
                schema_json = await lookup_agent.instance.get_schema(s_key)
                ledger_schema = json.loads(schema_json)
                log_json("Schema found on ledger:", ledger_schema, LOGGER)
                return ResolvedSchema(
                    None,
                    s_id,
                    schema_name,
                    schema_version,
                    origin_did,
                    ledger_schema["attrNames"],
                )
            except AbsentSchema:
                pass
        raise IndyConfigError("Issuer schema not found: {}/{}".format(schema_name, schema_version))

    async def _construct_proof(self, holder_id: str, proof_req: ProofRequest,
                               cred_ids: set = None) -> ConstructedProof:
        """
        Construct a proof from credentials in the holder's wallet, given a proof request
        """
        holder = self._agents.get(holder_id)
        if not holder:
            raise IndyConfigError("Unknown holder id: {}".format(holder_id))
        if not holder.is_holder:
            raise IndyConfigError(
                "Cannot construct proof from non-holder agent: {}".format(holder.agent_id))
        if not holder.synced:
            raise IndyConfigError("Holder is not yet synchronized: {}".format(holder_id))
        log_json("Fetching credentials for request", proof_req.data, LOGGER)

        # TODO - use separate request to find credentials and allow manual filtering?
        if cred_ids:
            LOGGER.debug("Construct proof from IDs: %s", cred_ids)
            found_creds = []
            for cred_id in cred_ids:
                try:
                    found_cred_json = await holder.instance.get_cred_info_by_id(
                        cred_id,
                    )
                    found_creds.append(json.loads(found_cred_json))
                except AbsentCred:
                    LOGGER.warning("Credential not found: %s", cred_id)

            if not found_creds:
                raise IndyError("No credentials found for proof")
            _populate_cred_def_ids(proof_req.data, found_creds)
            found_creds = proof_req_infos2briefs(proof_req.data, found_creds)
        else:
            # DEBUG
            #proof_req.wql_filters = {
            #    'eb8cce736d877a9a45bcc62303e62d25c0fe5da6_attr1_uuid': {
            #        'attr::attr1::value': '5'
            #    }
            #}

            _cred_ids, found_creds_json = await holder.instance.get_cred_briefs_by_proof_req_q(
                json.dumps(proof_req.data),
                json.dumps(proof_req.wql_filters) if proof_req.wql_filters else None,
            )
            found_creds = json.loads(found_creds_json)
            _populate_cred_def_ids(proof_req.data, found_creds)

        log_json("Found credentials", found_creds, LOGGER)

        if not found_creds:
            raise IndyError("No credentials found for proof")
        elif len(found_creds) > 1:
            raise IndyError("Too many credentials found for proof")

        request_params = proof_req_briefs2req_creds(proof_req.data, found_creds)

        # FIXME catch exception?
        log_json("Creating proof", request_params, LOGGER)
        proof_json = await holder.instance.create_proof(
            proof_req.data,
            found_creds,
            request_params,
        )
        proof = json.loads(proof_json)
        return ConstructedProof(proof)

    def _add_proof_spec(self, **params) -> str:
        """
        Add a proof request specification

        Args:
            params: parameters to be passed to the :class:`ProofSpecCfg` constructor
        """
        cfg = ProofSpecCfg(**params)
        if not cfg.spec_id:
            cfg.spec_id = _make_id("proof-")
        if cfg.spec_id in self._proof_specs:
            raise IndyConfigError("Duplicate proof spec ID: {}".format(cfg.spec_id))
        self._proof_specs[cfg.spec_id] = cfg
        return cfg.spec_id

    async def _sync_proof_spec(self, spec: ProofSpecCfg) -> bool:
        """
        Resolve schema information for a proof specification
        """
        missing = spec.get_incomplete_schemas()
        check = False
        for s_key in missing:
            try:
                found = await self._resolve_schema(*s_key)
                cfg = SchemaCfg(
                    found.schema_name, found.schema_version,
                    found.attr_names, found.origin_did)
                spec.populate_schema(cfg)
                check = True
            except IndyConfigError:
                pass
        if check:
            missing = spec.get_incomplete_schemas()
        spec.synced = not missing
        return spec.synced

    def _get_proof_spec_status(self, spec_id: str) -> ServiceResponse:
        """
        Return the status of a registered proof spec

        Args:
            spec_id: the unique identifier of the proof specification
        """
        if spec_id in self._proof_specs:
            msg = ProofSpecStatus(spec_id, self._proof_specs[spec_id].status)
        else:
            msg = IndyServiceFail("Unregistered proof spec: {}".format(spec_id))
        return msg

    async def _generate_proof_request(self, spec_id: str, wql_filters: dict = None) -> ProofRequest:
        """
        Create a proof request from a previously registered proof specification
        """
        spec = self._proof_specs.get(spec_id)
        if not spec:
            raise IndyConfigError("Proof specification not defined: {}".format(spec_id))
        if not spec.synced:
            raise IndyConfigError("Proof specification not synced: {}".format(spec_id))
        return _prepare_proof_request(spec, wql_filters)

    async def _request_proof(self, connection_id: str, proof_req: ProofRequest,
                             cred_ids: set = None, params: dict = None) -> VerifiedProof:
        """
        Request a verified proof from a connection
        """
        conn = self._connections.get(connection_id)
        if not conn:
            raise IndyConfigError("Unknown connection id: {}".format(connection_id))
        if not conn.synced:
            raise IndyConfigError("Connection is not yet synchronized: {}".format(connection_id))
        verifier = self._agents[conn.agent_id]
        if not verifier.is_verifier:
            raise IndyConfigError(
                "Cannot verify proof from non-verifier agent: {}".format(verifier.agent_id))
        if not verifier.synced:
            raise IndyConfigError("Verifier is not yet synchronized: {}".format(verifier.agent_id))
        proof = await conn.instance.construct_proof(proof_req, cred_ids, params)
        return await self._verify_proof(verifier.agent_id, proof_req, proof)

    async def _verify_proof(self, verifier_id: str, proof_req: ProofRequest,
                            proof: ConstructedProof) -> VerifiedProof:
        """
        Verify a constructed proof

        Args:
            verifier_id: the verifier agent to employ
            proof_req: the proof request to verify against
            proof: the constructed proof to verify
        """
        verifier = self._agents.get(verifier_id)
        if not verifier:
            raise IndyConfigError("Unknown verifier id: {}".format(verifier_id))
        if not verifier.synced:
            raise IndyConfigError("Verifier is not yet synchronized: {}".format(verifier.agent_id))
        result = await verifier.instance.verify_proof(proof_req.data, proof.proof)
        parsed_proof = revealed_attrs(proof.proof)
        return VerifiedProof(result, parsed_proof, proof)

    async def _resolve_nym(self, did: str, agent_id: str = None) -> ResolvedNym:
        """
        Resolve a DID on the ledger

        Args:
            did: the DID to resolve
            agent_id: the agent instance to employ
        """
        if not agent_id:
            for aid in self._agents:
                if self._agents[aid].synced:
                    agent_id = aid
                    break
        agent = self._agents.get(agent_id)
        if not agent:
            raise IndyConfigError("Unknown agent id: {}".format(agent_id))
        if not agent.synced:
            raise IndyConfigError("Agent is not yet synchronized: {}".format(agent.agent_id))
        nym_json = await agent.instance.get_nym(did)
        nym_info = json.loads(nym_json)
        if not nym_info:
            nym_info = None
        return ResolvedNym(did, nym_info)

    async def _handle_ledger_status(self):
        """
        Download the ledger status from von-network and return it to the client
        """
        url = self._ledger_url
        async with self.http as client:
            response = await client.get("{}/status".format(url))
        return await response.text()

    def _connection_http_client(self, conn_id: str = None, **kwargs):
        """
        Create a new :class:`ClientSession` which includes DID signing information in each request

        Args:
            conn_id: an optional identifier for a specific connection (to enable DID signing)
        Returns:
            the initialized :class:`ClientSession` object
        """
        if "request_class" not in kwargs:
            kwargs["request_class"] = SignedRequest
        if conn_id and "auth" not in kwargs:
            kwargs["auth"] = self._signed_request_auth(conn_id)
        return super(IndyService, self).http_client(**kwargs)

    def _signed_request_auth(self, conn_id: str, header_list=None):
        """
        Create a :class:`SignedRequestAuth` representing our authentication credentials,
        used to sign outgoing requests

        Args:
            conn_id: the unique identifier of the connection
            header_list: optionally override the list of headers to sign
        """
        conn = self._connections.get(conn_id)
        if not conn:
            raise IndyConfigError("Unknown connection ID: {}".format(conn_id))
        agent = self._agents[conn.agent_id]
        wallet = self._wallets[agent.wallet_id]
        if agent.did and wallet.seed:
            key_id = "did:sov:{}".format(agent.did)
            secret = wallet.seed
            if isinstance(secret, str):
                if secret[-1:] == "=":
                    secret = base64.b64decode(secret)
                else:
                    secret = bytes(secret, "ascii")
            ret = SignedRequestAuth(key_id, "ed25519", secret, header_list)
            if not conn.sign_target and hasattr(ret, "sign_target"):
                ret.sign_target = False
            return ret
        return None

    async def _service_request(self, request: ServiceRequest) -> ServiceResponse:
        """
        Process a message from the exchange and send the reply, if any

        Args:
            request: the message to be processed
        """
        if isinstance(request, LedgerStatusReq):
            with self._timer("ledger_status"):
                text = await self._handle_ledger_status()
                reply = LedgerStatus(text)

        elif isinstance(request, RegisterAgentReq):
            try:
                agent_id = self._add_agent(request.agent_type, request.wallet_id, **request.config)
                reply = self._get_agent_status(agent_id)
                self._sync_required()
            except IndyError as e:
                reply = IndyServiceFail(str(e))

        elif isinstance(request, RegisterConnectionReq):
            try:
                connection_id = self._add_connection(
                    request.connection_type, request.agent_id, **request.config)
                reply = self._get_connection_status(connection_id)
                self._sync_required()
            except IndyError as e:
                reply = IndyServiceFail(str(e))

        elif isinstance(request, RegisterCredentialTypeReq):
            try:
                self._add_credential_type(
                    request.issuer_id,
                    request.schema_name,
                    request.schema_version,
                    request.origin_did,
                    request.attr_names,
                    request.config)
                reply = IndyServiceAck()
            except IndyError as e:
                reply = IndyServiceFail(str(e))

        elif isinstance(request, RegisterWalletReq):
            try:
                wallet_id = self._add_wallet(**request.config)
                reply = self._get_wallet_status(wallet_id)
                self._sync_required()
            except IndyError as e:
                reply = IndyServiceFail(str(e))

        elif isinstance(request, AgentStatusReq):
            reply = self._get_agent_status(request.agent_id)

        elif isinstance(request, ConnectionStatusReq):
            reply = self._get_connection_status(request.connection_id)

        elif isinstance(request, WalletStatusReq):
            reply = self._get_wallet_status(request.wallet_id)

        elif isinstance(request, IssueCredentialReq):
            try:
                with self._timer("issue_credential"):
                    reply = await self._issue_credential(
                        request.connection_id,
                        request.schema_name,
                        request.schema_version,
                        request.origin_did,
                        request.cred_data)
            except IndyError as e:
                reply = IndyServiceFail(str(e))

        elif isinstance(request, IssueCredentialBatchReq):
            try:
                with self._timer("issue_credential"):
                    reply = await self._issue_credential(
                        request.connection_id,
                        request.schema_name,
                        request.schema_version,
                        request.origin_did,
                        request.cred_data,
                        True)
            except IndyError as e:
                reply = IndyServiceFail(str(e))

        elif isinstance(request, GenerateCredentialRequestReq):
            try:
                with self._timer("generate_credential_request"):
                    reply = await self._generate_credential_request(
                        request.holder_id, request.cred_offer)
            except IndyError as e:
                reply = IndyServiceFail(str(e))

        elif isinstance(request, StoreCredentialReq):
            try:
                with self._timer("store_credential"):
                    reply = await self._store_credential(
                        request.holder_id, request.credential)
            except IndyError as e:
                reply = IndyServiceFail(str(e))

        elif isinstance(request, ResolveSchemaReq):
            try:
                with self._timer("resolve_schema"):
                    reply = await self._resolve_schema(
                        request.schema_name, request.schema_version, request.origin_did)
            except IndyError as e:
                reply = IndyServiceFail(str(e))

        elif isinstance(request, ConstructProofReq):
            try:
                with self._timer("construct_proof"):
                    reply = await self._construct_proof(
                        request.holder_id, request.proof_req, request.cred_ids)
            except IndyError as e:
                reply = IndyServiceFail(str(e))

        elif isinstance(request, RegisterProofSpecReq):
            try:
                spec_id = self._add_proof_spec(**request.config)
                reply = self._get_proof_spec_status(spec_id)
                self._sync_required()
            except IndyError as e:
                reply = IndyServiceFail(str(e))

        elif isinstance(request, GenerateProofRequestReq):
            try:
                reply = await self._generate_proof_request(request.spec_id, request.wql_filters)
            except IndyError as e:
                reply = IndyServiceFail(str(e))

        elif isinstance(request, RequestProofReq):
            try:
                with self._timer("request_proof"):
                    reply = await self._request_proof(
                        request.connection_id, request.proof_req,
                        request.cred_ids, request.params)
            except IndyError as e:
                reply = IndyServiceFail(str(e))

        elif isinstance(request, VerifyProofReq):
            try:
                with self._timer("verify_proof"):
                    reply = await self._verify_proof(
                        request.verifier_id, request.proof_req, request.proof)
            except IndyError as e:
                reply = IndyServiceFail(str(e))

        elif isinstance(request, ResolveNymReq):
            try:
                with self._timer("resolve_nym"):
                    reply = await self._resolve_nym(request.did, request.agent_id)
            except IndyError as e:
                reply = IndyServiceFail(str(e))

        else:
            reply = None
        return reply
