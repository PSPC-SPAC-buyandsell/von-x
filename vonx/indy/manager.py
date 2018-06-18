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

from ..common.manager import ConfigServiceManager
from .client import IndyClient
from .service import IndyService

LOGGER = logging.getLogger(__name__)

class IndyManager(ConfigServiceManager):

    def _init_services(self):
        super(IndyManager, self)._init_services()

        indy = self.init_indy_service()
        self.add_service("indy", indy)
        self._client = IndyClient(self.get_request_target("indy"))

    def init_indy_service(self, pid: str = "indy") -> IndyService:
        """
        Initialize the Hyperledger Indy service

        Args:
            pid: the identifier for the :class:`IndyService` instance
        """
        genesis_path = self._env.get("INDY_GENESIS_PATH")
        if not genesis_path:
            raise ValueError(
                "Indy genesis transaction path (INDY_GENESIS_PATH) not defined"
            )
        ledger_url = self._env.get("INDY_LEDGER_URL")
        if not ledger_url:
            raise ValueError("INDY_LEDGER_URL not defined")

        spec = {
            "auto_register": self._env.get("AUTO_REGISTER_DID", 1),
            "genesis_path": genesis_path,
            "ledger_url": ledger_url,
        }
        LOGGER.info("Initializing Indy service")
        return IndyService(pid, self._exchange, self._env, spec)


class TestIndyManager(IndyManager):
    async def _service_sync(self):
        LOGGER.info("setting up test indy issuer")
        wallet_id = await self._client.register_wallet({
            "name": "issuer-wallet",
            "seed": "issuer-wallet-000000000000000000",
        })
        issuer_id = await self._client.register_issuer(wallet_id, {
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
        await self._client.register_credential_type(
            issuer_id,
            "test.schema",
            "1.0.0",
            None,
            ["attr1", "attr2"],
            {"source_claim": "attr1", "mapping": mapping})
        conn_id = await self._client.register_orgbook_connection(
            issuer_id, {
                "api_url": "http://192.168.65.3:8081/api/v2",
            })
        await self._client.issue_credential(
            conn_id, {
            })

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
    #console.setFormatter(logging.Formatter(fmt=SCREEN_FORMAT))
    logger.addHandler(console)

    mgr = TestIndyManager()
    mgr.start()
