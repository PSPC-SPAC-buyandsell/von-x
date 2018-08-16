import asyncio
import logging
import os
import sys

from vonx.indy.manager import IndyManager

LOGGER = logging.getLogger()


class TestIndyIssuer(IndyManager):
    """
    A test Indy service manager which creates sample wallets and issuers
    """

    schema_name = "test.schema"
    schema_version = "1.0.0"


    def get_service_init_params(self) -> dict:
        return {
            "auto_register": 1,
            "genesis_path": "/home/indy/genesis",
            "ledger_url": os.environ.get("LEDGER_URL") or "http://192.168.65.3:9000",
        }

    async def _load_config(self) -> None:
        # skip default implementation
        pass

    async def add_test_services(self, client):
        LOGGER.info("setting up test indy issuer")
        holder_url = os.environ.get("HOLDER_API") or "http://192.168.65.3:5001/holder"

        all = {}

        all["issuer_wallet_id"] = await client.register_wallet({
            "name": "issuer-wallet",
            "seed": "issuer-wallet-000000000000000001",
        })
        all["issuer_id"] = await client.register_issuer(all["issuer_wallet_id"], {
            "name": "Test Issuer",
            "email": "test@example.ca",
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

        all["holder_conn_id"] = await client.register_http_connection(
            all["issuer_id"], {
                "id": "holder",
                "api_url": holder_url,
            }
        )

        all["verifier_wallet_id"] = await client.register_wallet({
            "name": "verifier-wallet",
            "seed": "verifier-wallet-0000000000000001",
        })
        all["verifier_id"] = await client.register_verifier(all["verifier_wallet_id"], {
            "name": "Test Verifier",
        })
        all["verifier_conn_id"] = await client.register_http_connection(
            all["verifier_id"], {
                "id": "verifier",
                "api_url": holder_url,
            }
        )
        proof_spec = {
            "id": "test-proof",
            "version": "1.0.0",
            "schemas": [
                {
                    "key": {
                        # "did": "PXocv6sBRa7YefPvnHpsqp",
                        "name": self.schema_name,
                        "version": self.schema_version,
                    },
                    #"predicates": [
                    #    {
                    #        "name": "attr1",
                    #        "p_type": ">=",
                    #        "p_value": 1,
                    #    }
                    #]
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


    async def test_issue_cred(self, client, conn_id) -> str:
        stored = await client.issue_credential(
            conn_id, self.schema_name, self.schema_version, None,
            {"attr1": "Test", "attr2": "Second Value"})
        LOGGER.info("issued: %s", stored.cred_id)
        return stored.cred_id


    async def test_proof(self, client, conn_id, spec_id, cred_ids=None):
        proof_req = await client.generate_proof_request(spec_id)
        #cred_ids = None
        result = await client.request_proof(conn_id, proof_req, cred_ids)
        LOGGER.info("test proof verified: %s, result: %s", result.verified, result.parsed_proof)


def test_web(manager):
    from vonx.web import init_web
    app = init_web(manager)

    from aiohttp import web
    web.run_app(app, host='0.0.0.0', port=5000)


if __name__ == '__main__':
    LOGGER.setLevel(logging.DEBUG)
    CONSOLE = logging.StreamHandler()
    CONSOLE.setLevel(os.environ.get("LOG_LEVEL", logging.INFO))
    LOGGER.addHandler(CONSOLE)

    MGR = TestIndyIssuer()
    MGR.start()

    TEST = sys.argv[1] if len(sys.argv) > 1 else "proof"

    CLIENT = MGR.get_client()
    DONE = False
    async def setup(client, teardown=False):
        ids = await MGR.add_test_services(client)
        if TEST == "proof" and await client.sync():
            cred_id = await MGR.test_issue_cred(client, ids["holder_conn_id"])
            await MGR.test_proof(client, ids["verifier_conn_id"], ids["proof_spec_id"], {cred_id})
        if teardown:
            MGR.stop()

    try:
        asyncio.get_event_loop().run_until_complete(setup(CLIENT, TEST != "web"))

        if TEST == "web":
            test_web(MGR)
    except:
        LOGGER.exception("Error during init")
        MGR.stop()

    LOGGER.info("done")
