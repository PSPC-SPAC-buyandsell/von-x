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

from aiohttp import web
from aiohttp.helpers import BasicAuth

LOGGER = logging.getLogger(__name__)
REMOVE_HEADERS = {
    'authorization',
    'connection',
    'forwarded',
    'host',
    'proxy-connection',
    'via',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-port',
    'x-forwarded-proto',
}


def proxy_handler(proxy):
    """
    A simple web proxy, not designed for large posts. This allows an Issuer service
    to make requests via von-x without knowing the web address of TheOrgBook, for instance
    """

    async def handle_request(request):
        path = request.match_info['path']
        target_url = proxy['url']
        if not target_url.endswith('/'):
            target_url += '/'
        target_url += path

        headers = {} # use multidict?
        for header_name, header_value in request.headers.items():
            if header_name.lower() not in REMOVE_HEADERS:
                headers[header_name] = header_value
        auth = None
        if 'auth' in proxy and proxy['auth'].get('type') == 'basic':
            auth = BasicAuth(proxy['auth']['user'], proxy['auth']['password'])
        # TODO set Forwarded header?

        mgr = request.app['manager']
        async with mgr.executor.http as session:
            data = await session.request(
                request.method,
                target_url,
                auth=auth,
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
