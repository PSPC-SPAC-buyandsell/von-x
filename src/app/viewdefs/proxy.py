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
from sanic import response

LOGGER = logging.getLogger(__name__)


class ProxyConnHandler:
    """
    Maintain a single connection pool to support keepalives
    """
    def __init__(self):
        self._connector = None

    def get_connector(self):
        # Deferring connection pool until used
        # also avoids an odd error in uvloop when created globally
        if not self._connector:
            self._connector = aiohttp.TCPConnector()
        return self._connector

    def create_session(self, *args, **kwargs):
        kwargs['connector'] = self.get_connector()
        return aiohttp.ClientSession(*args, **kwargs)


def get_proxy_handler(proxy, conn_handler):

    async def handle_request(request, path):
        target_url = proxy['url']
        if not target_url.endswith('/'):
            target_url += '/'
        target_url += path

        headers = request.headers.copy()
        if 'x-forwarded-for' in headers:
            headers['x-forwarded-for'] += ', ' + request.ip
        else:
            headers['x-forwarded-for'] = request.ip

        session = conn_handler.create_session()
        data = await session.request(
            request.method,
            target_url,
            headers=headers,
            params=request.args,
            data=request.body)

        async def stream_content(client_response):
            while True:
                chunk = await data.content.read(4096)
                if not chunk:
                    break
                client_response.write(chunk)
            #await session.close()
        return response.stream(stream_content, headers=dict(data.headers))

    return handle_request
