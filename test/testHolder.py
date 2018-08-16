import asyncio
import logging
import os
import sys

from vonx.indy.manager import IndyManager

LOGGER = logging.getLogger()


class TestIndyHolder(IndyManager):
    """
    A test Indy service manager which creates a sample holder
    """

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
        LOGGER.info("setting up test indy holder")

        all = {}
        all["holder_wallet_id"] = await client.register_wallet({
            "name": "holder-wallet",
            "seed": "holder-wallet-000000000000000002",
        })
        all["holder_id"] = await client.register_holder(all["holder_wallet_id"], {
            "id": "holder",
            "name": "Test Holder",
        })

        return all


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

    MGR = TestIndyHolder()
    MGR.start()

    CLIENT = MGR.get_client()
    DONE = False
    async def setup(client, teardown=False):
        ids = await MGR.add_test_services(client)
        if teardown:
            MGR.stop()

    try:
        asyncio.get_event_loop().run_until_complete(setup(CLIENT))
        test_web(MGR)
    except:
        LOGGER.exception("Error during init")
        MGR.stop()

    LOGGER.info("done")
