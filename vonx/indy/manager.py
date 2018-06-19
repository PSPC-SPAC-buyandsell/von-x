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
import logging

from ..common.config import load_config
from ..common.manager import ConfigServiceManager
from .client import IndyClient
from .config import IndyConfigError, SchemaManager
from .service import IndyService

LOGGER = logging.getLogger(__name__)


def load_credential_type(ctype, schema_mgr: SchemaManager) -> dict:
    """
    Load the credential types defined by our config into a standard format
    """
    if "source_claim" not in ctype:
        raise IndyConfigError("Credential type must define 'source_claim'")
    if "schema" not in ctype:
        raise IndyConfigError("Credential type must define 'schema'")
    if isinstance(ctype["schema"], str):
        name = ctype["schema"]
        version = None
        origin_did = None
        attributes = None
    elif isinstance(ctype["schema"], dict):
        name = ctype["schema"].get("name")
        version = ctype["schema"].get("version")
        origin_did = ctype["schema"].get("origin_did")
        attributes = ctype["schema"].get("attributes")
    else:
        raise IndyConfigError("Credential type schema must be string or dict")
    if not name:
        raise IndyConfigError("Credential type schema missing 'name'")
    if not version or not (attributes or origin_did):
        schema = schema_mgr.find(name, version)
        if schema:
            version = schema.version
            attributes = schema.attr_names
            origin_did = schema.origin_did
        else:
            raise IndyConfigError(
                "Schema definition not found: {} {}".format(name, version)
            )
    ret = {
        "schema_name": name,
        "schema_version": version,
        "origin_did": origin_did,
        "attributes": attributes,
        "params": {
            "source_claim": ctype["source_claim"],
        }
    }
    if "description" in ctype:
        ret["params"]["description"] = ctype["description"]
    if "issuer_url" in ctype:
        ret["params"]["issuer_url"] = ctype["issuer_url"]
    if "mapping" in ctype:
        ret["params"]["mapping"] = ctype["mapping"]
    return ret


class IndyManager(ConfigServiceManager):

    def _init_services(self):
        super(IndyManager, self)._init_services()

        indy = self.init_indy_service()
        self.add_service("indy", indy)
        self._schema_mgr = None

    def get_client(self) -> IndyClient:
        return IndyClient(self.get_service_request_target("indy"))

    def init_indy_service(self, pid: str = "indy") -> IndyService:
        """
        Initialize the Hyperledger Indy service

        Args:
            pid: the identifier for the :class:`IndyService` instance
        """
        genesis_path = self._env.get("INDY_GENESIS_PATH")
        if not genesis_path:
            raise IndyConfigError(
                "Indy genesis transaction path (INDY_GENESIS_PATH) not defined"
            )
        ledger_url = self._env.get("INDY_LEDGER_URL")
        if not ledger_url:
            raise IndyConfigError("INDY_LEDGER_URL not defined")

        spec = {
            "auto_register": self._env.get("AUTO_REGISTER_DID", 1),
            "genesis_path": genesis_path,
            "ledger_url": ledger_url,
        }
        LOGGER.info("Initializing Indy service")
        return IndyService(pid, self._exchange, self._env, spec)

    async def _service_start(self) -> bool:
        ret = await super(IndyManager, self)._service_start()
        if ret:
            self._load_schemas()
        return ret

    async def _service_sync(self):
        await super(IndyManager, self)._service_sync()
        await self._register_agents()

    def _load_schemas(self):
        self._schema_mgr = SchemaManager()
        std = load_config('vonx.config:schemas.yml')
        if std:
            self._schema_mgr.load(std)
        ext = self.load_config_path('SCHEMAS_CONFIG_PATH', 'schemas.yml')
        if ext:
            self._schema_mgr.load(ext)

    async def _register_agents(self) -> None:
        """
        Load agent settings from our configuration files
        """
        issuers = []
        issuer_ids = []
        limit_issuers = self._env.get("ISSUERS")
        limit_issuers = (
            limit_issuers.split()
            if (limit_issuers and limit_issuers != "all")
            else None
        )
        config_issuers = self.services_config("issuers")
        if not config_issuers:
            raise IndyConfigError("No issuers defined by configuration")
        for issuer_key, issuer_cfg in config_issuers.items():
            if not "id" in issuer_cfg:
                issuer_cfg["id"] = issuer_key
            if limit_issuers is None or issuer_cfg["id"] in limit_issuers:
                issuers.append(issuer_cfg)
                issuer_ids.append(issuer_cfg["id"])
        if issuers:
            client = self.get_client()
            for issuer_cfg in issuers:
                await self._register_issuer(client, issuer_cfg)
        else:
            raise IndyConfigError("No defined issuers referenced by ISSUERS")

    async def _register_issuer(self, client: IndyClient, issuer_cfg: dict) -> None:
        issuer_id = issuer_cfg["id"]
        if "wallet" not in issuer_cfg:
            raise IndyConfigError("Wallet not defined for issuer: {}".format(issuer_id))
        wallet_cfg = issuer_cfg["wallet"]
        del issuer_cfg["wallet"]
        if "credential_types" not in issuer_cfg:
            raise IndyConfigError("Missing credential_types for issuer: {}".format(issuer_id))
        cred_types = issuer_cfg["credential_types"]
        del issuer_cfg["credential_types"]
        if "connection" in issuer_cfg:
            connection_cfg = issuer_cfg["connection"]
            del issuer_cfg["connection"]
        else:
            connection_cfg = {
                "api_url": self._env.get("TOB_API_URL"),
            }

        if not wallet_cfg.get("name"):
            wallet_cfg["name"] = issuer_id + "-Issuer-Wallet"
        if not wallet_cfg.get("seed"):
            raise IndyConfigError("Missing wallet seed for issuer: {}".format(issuer_id))
        wallet_id = await client.register_wallet(wallet_cfg)
        issuer_id = await client.register_issuer(wallet_id, issuer_cfg)

        for type_spec in cred_types:
            cred_type = load_credential_type(type_spec, self._schema_mgr)
            await client.register_credential_type(
                issuer_id,
                cred_type["schema_name"],
                cred_type["schema_version"],
                cred_type["origin_did"],
                cred_type["attributes"],
                cred_type["params"],
            )

        if "id" not in connection_cfg:
            connection_cfg["id"] = issuer_id
        conn_id = await client.register_orgbook_connection(
            issuer_id, connection_cfg)


class TestIndyManager(IndyManager):
    async def _service_sync(self):
        client = self.get_client()

        LOGGER.info("setting up test indy issuer")

        wallet_id = await client.register_wallet({
            "name": "issuer-wallet",
            "seed": "issuer-wallet-000000000000000001",
        })
        issuer_id = await client.register_issuer(wallet_id, {
            "email": "test@example.ca",
            "name": "Test Issuer",
        })
        mapping = [
            {
                "model": "name",
                "fields": {
                    "text": {
                        "input": "attr1",
                        "from": "claim"
                    },
                    "type": {
                        "input": "legal_name",
                        "from": "value"
                    }
                }
            }
        ]
        schema_name = "test.schema"
        schema_version = "1.0.0"
        await client.register_credential_type(
            issuer_id,
            schema_name,
            schema_version,
            None,
            ["attr1", "attr2"],
            {
                "description": "Test Credential",
                "source_claim": "attr1",
                "mapping": mapping,
            })
        conn_id = await client.register_orgbook_connection(
            issuer_id, {
                "api_url": "http://192.168.65.3:8081/api/v2",
            })
        synced = False
        wait = 10
        while not synced and wait > 0:
            await asyncio.sleep(1)
            status = await client.get_connection_status(conn_id)
            synced = status["synced"]
            wait -= 1
        if synced:
            result = await client.issue_credential(
                conn_id, schema_name, schema_version, None,
                {"attr1": "Test Name", "attr2": "Second Value"})
            LOGGER.info("issued: %s", result)
        else:
            LOGGER.info("Connection took too long to sync")

    def init_indy_service(self, pid: str = "indy") -> IndyService:
        spec = {
            "auto_register": 1,
            "genesis_path": "/home/indy/genesis",
            "ledger_url": "http://192.168.65.3:9000",
        }
        LOGGER.info("init indy")
        return IndyService(pid, self._exchange, self._env, spec)


if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    logger.addHandler(console)

    mgr = TestIndyManager()
    mgr.start()
