import aiohttp
import asyncio
import async_timeout

URL='http://localhost:5000/test'
BATCH=100
RUNS=1

async def fetch(session, url):
    async with async_timeout.timeout(30):
        #async with session.post(url, json={'test': 'object'})
        async with session.get(url) as response:
            return response.status

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [
            asyncio.ensure_future(fetch(session, URL))
            for i in range(BATCH)
        ]
        responses = await asyncio.gather(*tasks)
        print(responses)

loop = asyncio.get_event_loop()
loop.run_until_complete(main())
