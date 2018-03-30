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

import aiohttp
from aiohttp import web

LOGGER = logging.getLogger(__name__)


def proxy_handler(proxy):
    """
    A simple web proxy, not designed for large posts.
    """

    async def handle_request(request):
        path = request.match_info['path']
        target_url = proxy['url']
        if not target_url.endswith('/'):
            target_url += '/'
        target_url += path

        headers = request.headers.copy()
        #if 'x-forwarded-for' in headers:
        #    headers['x-forwarded-for'] += ', ' + request.ip
        #else:
        #    headers['x-forwarded-for'] = request.ip

        async with request.app['manager'].http_client() as session:
            data = await session.request(
                request.method,
                target_url,
                headers=headers,
                params=request.query,
                data=await request.content.read())

            response = web.StreamResponse(
                status=data.status,
                reason=data.reason,
                headers=data.headers
            )
            await response.prepare(request)

            while True:
                chunk = await data.content.read(4096)
                if not chunk:
                    break
                await response.write(chunk)
                #await response.drain()

        return response

    return handle_request