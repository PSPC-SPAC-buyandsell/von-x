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
from typing import Mapping, Sequence
import uuid

from von_agent.agents import (
    _BaseAgent,
    Issuer,
    HolderProver,
    Verifier,
)
from von_agent.nodepool import NodePool
from von_agent.wallet import Wallet

from .connection import ConnectionBase, ConnectionType
from .errors import IndyConfigError
from .tob import TobConnection


class AgentType(Enum):
    issuer = "issuer"
    holder = "holder"
    verifier = "verifier"


class AgentCfg:
    """
    Manage configuration settings for an Agent, including schemas bound for the ledger
    """
    def __init__(self, agent_type: str, wallet_id: str, **params):
        self.agent_id = params.get("id")
        try:
            self.agent_type = AgentType(agent_type)
        except KeyError:
            raise IndyConfigError("Unsupported agent type: {}".format(agent_type))
        self.cred_types = []
        self._instance = None
        self.opened = False
        self.registered = False
        self.synced = False
        self.wallet_id = wallet_id
        self.abbreviation = params.get("abbreviation")
        self.email = params.get("email")
        self.endpoint = params.get("endpoint")
        self.name = params.get("name")
        self.url = params.get("url")

    @property
    def created(self) -> bool:
        return self.instance is not None

    @property
    def did(self) -> str:
        return self._instance and self._instance.did

    @property
    def extended_config(self) -> dict:
        """
        Accessor for the extended Agent configuration
        """
        ret = {}
        if self.endpoint:
            ret["endpoint"] = self.endpoint
        return ret

    @property
    def instance(self) -> _BaseAgent:
        return self._instance

    @property
    def role(self) -> str:
        return "TRUST_ANCHOR" if self.agent_type == AgentType.issuer else ""

    @property
    def status(self) -> dict:
        """
        Get the current status of the agent
        """
        return {
            "did": self.did,
            "created": self.created,
            "opened": self.opened,
            "registered": self.registered,
            "synced": self.synced,
        }

    @property
    def verkey(self) -> str:
        return self._instance and self._instance.verkey

    async def create(self, wallet: 'WalletCfg') -> None:
        if not self._instance:
            if self.agent_type == AgentType.issuer:
                cls = Issuer
            elif self.agent_type == AgentType.holder:
                cls = HolderProver
            elif self.agent_type == AgentType.verifier:
                cls = Verifier
            else:
                raise IndyConfigError("Unknown agent type")
            self._instance = cls(wallet.instance, self.extended_config)
        await self.open()

    async def open(self) -> None:
        if not self.opened:
            self.opened = await self._instance.open()
            if isinstance(self._instance, HolderProver):
                # NOTE: should only create this once,
                # and only in the root wallet (virtual_wallet == None)
                await self._instance.create_link_secret(str(uuid.uuid4()))

    def add_credential_type(self, schema: 'SchemaCfg', **params) -> None:
        """
        Add a credential type to the Agent configuration

        Args:
            schema: the :class:`SchemaCfg` to be added
        """
        if self.agent_type != AgentType.issuer:
            raise IndyConfigError("Only agent of type 'issuer' may publish schemas")
        self.cred_types.append({
            "definition": schema,
            "ledger_schema": None,
            "cred_def": None,
            "params": params,
        })

    def find_credential_type(self, name: str, version: str) -> dict:
        """
        Find the extended information for a specific schema, including the ledger schema
        definition and credential definition (if any)

        Args:
            name: the schema name to be located
            version: the schema version to be located
        """
        match = SchemaCfg(name, version)
        for cred_type in self.cred_types:
            if cred_type["definition"].compare(match):
                return cred_type
        return None

    def get_connection_params(self, connection: 'ConnectionCfg') -> dict:
        """
        Get parameters required for initializing the connection
        """
        cred_specs = []
        for cred_type in self.cred_types:
            params = cred_type["params"]
            type_spec = {
                "schema": cred_type["definition"],
                "source_claim": params.get("source_claim"),
            }
            if "description" in params:
                type_spec["description"] = params["description"]
            if "issuer_url" in params:
                type_spec["issuer_url"] = params["issuer_url"]
            if "mapping" in params:
                type_spec["mapping"] = params["mapping"]
            cred_specs.append(type_spec)
        return {
            "abbreviation": self.abbreviation,
            "credential_types": cred_specs,
            "did": self.did,
            "email": self.email,
            "name": self.name,
            "url": self.url,
        }


class ConnectionCfg:
    """
    Manage configuration settings for a connection between an issuer and a target
    """
    def __init__(self, connection_type: str, agent_id: str, **params):
        self.connection_id = params.get("id")
        self.agent_id = agent_id
        try:
            self.connection_type = ConnectionType(connection_type)
        except KeyError:
            raise IndyConfigError("Unsupported connection type: {}".format(connection_type))
        self._instance = None
        self.connection_params = params
        self.opened = False
        self.synced = False

        if self.connection_type != ConnectionType.TheOrgBook:
            raise IndyConfigError("Only TOB connections are currently supported")

    @property
    def created(self) -> bool:
        return self._instance is not None

    @property
    def instance(self) -> ConnectionBase:
        return self._instance

    @property
    def status(self) -> dict:
        return {
            "created": self.created,
            "opened": self.opened,
            "synced": self.synced,
        }

    async def create(self, agent_params: dict) -> None:
        if self.connection_type == ConnectionType.TheOrgBook:
            self._instance = TobConnection(agent_params, self.connection_params)

    async def open(self, http_client) -> None:
        if not self.opened:
            self._instance.http_client = http_client
            await self._instance.open()
            self.opened = True

    async def sync(self, agent: AgentCfg) -> None:
        if not self.synced:
            await self._instance.sync()
            self.synced = True


class SchemaCfg:
    """
    A credential schema definition
    """
    def __init__(self, name: str, version: str, attributes=None, origin_did: str = None):
        self.name = name
        self.version = version
        self._attributes = []
        if attributes:
            self.attributes = attributes
        self.origin_did = origin_did

    @property
    def attributes(self) -> list:
        """
        Accessor for the extended schema attributes list

        Returns:
            a copy of the schema attributes
        """
        return self._attributes.copy()

    @attributes.setter
    def attributes(self, value) -> None:
        """
        Setter for the schema attributes list
        """
        self._attributes = []
        if isinstance(value, Mapping):
            for name, attr in value.items():
                self.add_attribute(attr, name)
        elif isinstance(value, Sequence):
            for attr in value:
                self.add_attribute(attr)
        else:
            raise IndyConfigError('Unsupported type for attributes: {}'.format(value))

    @property
    def attr_names(self) -> list:
        """
        Accessor for the schema attribute names

        Returns:
            the attribute names only
        """
        return tuple(attr['name'] for attr in self._attributes)

    def add_attribute(self, attr, name=None) -> None:
        """
        Add an attribute to the schema including optional type information

        Args:
            attr: a dict or str representing the attribute
            name: the name of the attribute
        """
        if isinstance(attr, Mapping):
            if name is not None:
                attr['name'] = name
            self._attributes.append(attr)
        elif isinstance(attr, str):
            attr = {'name': attr}
            self._attributes.append(attr)
        elif attr is None and name:
            self._attributes.append({'name': name})
        else:
            raise IndyConfigError('Unsupported type for attribute: {}'.format(attr))

    def copy(self) -> 'SchemaCfg':
        """
        Create a copy of this :class:`SchemaCfg` instance
        """
        return SchemaCfg(self.name, self.version, self._attributes)

    def validate(self, value) -> None:
        """
        Perform validation of a set of attribute values against the schema
        """
        pass

    def compare(self, schema: 'SchemaCfg') -> bool:
        """
        Check whether this schema instance and another are compatible.
        Note: schemas with an empty issuer DID will match schemas with a blank issuer DID,
        or the same DID
        """
        if self.name == schema.name and self.version == schema.version:
            if not self.origin_did or not schema.origin_did or self.origin_did == schema.origin_did:
                if not self.attributes or not schema.attributes \
                        or self.attributes == schema.attributes:
                    return True
        return False

    def __repr__(self) -> str:
        return 'SchemaCfg(name={}, version={})'.format(self.name, self.version)


class WalletCfg:
    """
    Manage configuration settings for an Indy wallet
    """
    def __init__(self, **params):
        self.wallet_id = params.get("id")
        self.name = params.get("name")
        if not self.name:
            raise IndyConfigError("Missing wallet name")
        self.seed = params.get("seed")
        if not self.seed:
            raise IndyConfigError("Missing seed for wallet '{}'".format(self.name))
        if len(self.seed) != 32:
            raise IndyConfigError(
                "Wallet seed length is not 32 characters: {}".format(self.seed)
            )
        self.type = params.get("type")  # default to virtual?
        self.params = params.get("params") or {}
        if "freshness_time" not in self.params:
            self.params["freshness_time"] = 0
        self.access_creds = params.get("access_creds") or {"key": ""}
        self._instance = None

    @property
    def created(self) -> bool:
        return self._instance and self._instance.created

    @property
    def instance(self) -> Wallet:
        return self._instance

    @property
    def opened(self) -> bool:
        return self._instance and self._instance.handle is not None

    @property
    def status(self) -> dict:
        return {
            "created": self.created,
            "opened": self.opened,
        }

    async def create(self, pool: NodePool) -> None:
        self._instance = Wallet(
            pool,
            self.seed,
            self.name,
            self.type,
            self.params,
            self.access_creds)
        await self.instance.create()

    async def open(self):
        await self._instance.open()
