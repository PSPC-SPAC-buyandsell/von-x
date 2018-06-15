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
    Issuer,
    HolderProver,
    Verifier,
)
from von_agent.nodepool import NodePool
from von_agent.wallet import Wallet

from .tob import TobClient


class AgentType(Enum):
    issuer = "issuer"
    holder = "holder"
    verifier = "verifier"

class IssuerTargetType(Enum):
    TheOrgBook = "TheOrgBook"
    vonx = "von-x"


class IndyConfigError(Exception):
    pass


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
        self.endpoint = params.get("endpoint")
        self.instance = None
        self.opened = False
        self.registered = False
        self.synced = False
        self.wallet_id = wallet_id

        self.cred_defs = []
        self.schemas = []

        schemas = params.get("schemas")
        if schemas:
            for schema in schemas:
                self.add_schema(schema)

    @property
    def created(self) -> bool:
        return self.instance is not None

    @property
    def did(self) -> str:
        return self.instance and self.instance.did

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
        return self.instance and self.instance.verkey

    async def create(self, wallet: 'WalletCfg') -> None:
        if self.agent_type == AgentType.issuer:
            cls = Issuer
        elif self.agent_type == AgentType.holder:
            cls = HolderProver
        elif self.agent_type == AgentType.verifier:
            cls = Verifier
        else:
            raise IndyConfigError("Unknown agent type")
        self.instance = cls(wallet.instance, self.extended_config)
        await self.open()

    async def open(self):
        self.opened = await self.instance.open()
        if isinstance(self.instance, HolderProver):
            # NOTE: should only create this once,
            # and only in the root wallet (virtual_wallet == None)
            await self.instance.create_link_secret(str(uuid.uuid4()))

    def add_schema(self, schema: 'SchemaCfg') -> None:
        """
        Add a schema to the Agent configuration

        Args:
            schema: the :class:`SchemaCfg` to be added
        """
        if self.agent_type != AgentType.issuer:
            raise IndyConfigError("Only agent of type 'issuer' may publish schemas")
        self.schemas.append({
            "definition": schema.copy(),
            "ledger": None,
            "cred_def": None,
        })

    def get_schema_config(self, name: str, version: str) -> dict:
        """
        Find the extended information for a specific schema, including the ledger schema
        definition and credential definition (if any)

        Args:
            name: the schema name to be located
            version: the schema version to be located
        """
        match = SchemaCfg(name, version)
        for schema in self.schemas:
            defn = schema["definition"]
            if defn.compare(match):
                return schema
        return None

    def get_sync_params(self, target: 'IssuerTargetCfg') -> dict:
        """
        Get parameters required for syncing with the target
        """
        return {}


class ConnectionCfg:
    """
    Manage configuration settings for a connection between an issuer and a target
    """
    def __init__(self, issuer_id: str, target_id: str, **params):
        self.connection_id = params.get("id")
        self.instance = None
        self.issuer_id = issuer_id
        self.target_id = target_id
        self.processor_config = params.get("processor_config")
        self.synced = False

    @property
    def created(self) -> bool:
        return self.instance is not None

    @property
    def status(self) -> dict:
        return {
            "created": self.created,
            "synced": self.synced,
        }

    async def create(self, target: 'IssuerTargetCfg', http_client: 'aiohttp.ClientSession') -> None:
        self.instance = await target.connect(http_client)

    async def sync(self, issuer: 'IssuerCfg', target: 'IssuerTargetCfg') -> None:
        params = issuer.get_sync_params(target)
        self.synced = await target.register_issuer(params)


class IssuerTargetCfg:
    """
    Manage configuration settings for an Indy issuer target
    """
    def __init__(self, target_type: str, **params):
        self.target_id = params.get("id")
        try:
            self.target_type = IssuerTargetType(target_type)
        except KeyError:
            raise IndyConfigError("Unsupported target type: {}".format(target_type))
        self.instance = None
        self.url = params.get("url")

        if self.target_type == IssuerTargetType.TheOrgBook:
            if not self.url:
                raise IndyConfigError("Missing URL for TheOrgBook: {}".format(self.target_id))

    @property
    def created(self) -> bool:
        return self.instance is not None

    @property
    def status(self) -> dict:
        return {
            "created": self.created,
        }

    async def create(self) -> None:
        pass

    async def connect(self, http_client) -> TobClient:
        if self.target_type == IssuerTargetType.TheOrgBook:
            self.instance = TobClient(http_client, self.url)


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
        self.instance = None

    @property
    def created(self) -> bool:
        return self.instance and self.instance.created

    @property
    def opened(self) -> bool:
        return self.instance and self.instance.handle is not None

    @property
    def status(self) -> dict:
        return {
            "created": self.created,
            "opened": self.opened,
        }

    async def create(self, pool: NodePool) -> None:
        self.instance = Wallet(
            pool,
            self.seed,
            self.name,
            self.type,
            self.params,
            self.access_creds)
        await self.instance.create()

    async def open(self):
        await self.instance.open()
