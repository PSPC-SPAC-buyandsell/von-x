import asyncio
import logging

from vonx.indy.manager import IndyManager
from vonx.indy.service import IndyService

LOGGER = logging.getLogger()


class TestIndyManager(IndyManager):
    """
    A test Indy service manager which creates sample wallets and issuers
    """

    schema_name = "test.schema"
    schema_version = "1.0.0"


    def init_indy_service(self, pid: str = "indy") -> IndyService:
        spec = {
            "auto_register": 1,
            "genesis_path": "/home/indy/genesis",
            "ledger_url": "http://192.168.65.3:9000",
        }
        LOGGER.info("init indy")
        return IndyService(pid, self._exchange, self._env, spec)

    async def _load_config(self) -> None:
        pass


    async def add_test_services(self, client):
        LOGGER.info("setting up test indy issuer")

        all = {}

        all["issuer_wallet_id"] = await client.register_wallet({
            "name": "issuer-wallet",
            "seed": "issuer-wallet-000000000000000001",
        })
        all["issuer_id"] = await client.register_issuer(all["issuer_wallet_id"], {
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
        await client.register_credential_type(
            all["issuer_id"],
            self.schema_name,
            self.schema_version,
            None,
            ["attr1", "attr2"],
            {
                "description": "Test Credential",
                "source_claim": "attr1",
                "mapping": mapping,
            }
        )

        #conn_id = await client.register_orgbook_connection(
        #    issuer_id, {
        #        "api_url": "http://192.168.65.3:8081/api/v2",
        #    })
        all["holder_wallet_id"] = await client.register_wallet({
            "name": "holder-wallet",
            "seed": "holder-wallet-000000000000000001",
        })
        all["holder_id"] = await client.register_holder(all["holder_wallet_id"], {
            "name": "Test Holder",
        })
        all["holder_conn_id"] = await client.register_holder_connection(
            all["issuer_id"], {
                "holder_id": all["holder_id"],
            }
        )

        all["verifier_wallet_id"] = await client.register_wallet({
            "name": "verifier-wallet",
            "seed": "verifier-wallet-0000000000000001",
        })
        all["verifier_id"] = await client.register_verifier(all["verifier_wallet_id"], {
            "name": "Test Verifier",
        })
        all["verifier_conn_id"] = await client.register_holder_connection(
            all["verifier_id"], {
                "holder_id": all["holder_id"],
            }
        )
        proof_spec = {
            "version": "1.0.0",
            "schemas": [
                {
                    "key": {
                        "name": self.schema_name,
                        "version": self.schema_version,
                    }
                }
            ]
        }
        all["proof_spec_id"] = await client.register_proof_spec(proof_spec)

        return all


    async def test_issue_creds(self, client, conn_id, count):
        LOGGER.info("--- issuing %s test credentials ---", count)
        creds = [self.test_issue_cred(client, conn_id)
                 for _ in range(count)]
        start = time.time()
        await asyncio.gather(*creds)
        dur = time.time() - start
        avg = dur / len(creds)
        LOGGER.info("--- issued %s creds in %s seconds, avg %s ---", len(creds), dur, avg)


    async def test_issue_cred(self, client, conn_id):
        (cred_id, _result) = await client.issue_credential(
            conn_id, self.schema_name, self.schema_version, None,
            {"attr1": "Test Name", "attr2": "Second Value"})
        LOGGER.info("issued: %s", cred_id)


    async def test_proof(self, client, conn_id, spec_id):
        proof_req = await client.generate_proof_request(spec_id)
        result = await client.request_proof(conn_id, proof_req)
        LOGGER.info("test proof: %s", result)


if __name__ == '__main__':
    LOGGER.setLevel(logging.DEBUG)
    CONSOLE = logging.StreamHandler()
    CONSOLE.setLevel(logging.INFO)
    LOGGER.addHandler(CONSOLE)

    MGR = TestIndyManager()
    MGR.start()

    client = MGR.get_client()
    async def setup(client):
        ids = await MGR.add_test_services(client)
        if await client.sync():
            await MGR.test_issue_cred(client, ids["holder_conn_id"])
            await MGR.test_proof(client, ids["verifier_conn_id"], ids["proof_spec_id"])
    asyncio.ensure_future(setup(client))

    async def auto_abort():
        await asyncio.sleep(5)
        while True:
            status = await client.get_status()
            if status.get("failed"):
                MGR.stop()
                return
            elif status.get("synced"):
                return
            await asyncio.sleep(2)
    asyncio.get_event_loop().run_until_complete(auto_abort())
    LOGGER.info("done")
    #import threading
    #LOGGER.info(threading.enumerate())
