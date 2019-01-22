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

"""
aiohttp connection tracing support, for debugging
"""

import logging

from aiohttp.tracing import TraceConfig

LOGGER = logging.getLogger(__name__)


class DebugTraceConfig(TraceConfig):
    """
    TraceConfig for logging HTTP interactions in aiohttp client
    """
    def __init__(self, logger: logging.Logger = None, log_level=None, **kwargs):
        super(DebugTraceConfig, self).__init__(**kwargs)
        self._log = logger or LOGGER
        self._log_level = log_level or logging.INFO
        self._register_handlers()

    def log(self, *msg):
        """
        Output log message
        """
        self._log.log(self._log_level, *msg)

    def _register_handlers(self):
        """
        Register all signal handlers
        """
        def handler(msg):
            async def handle(session, trace_config_ctx, params):
                if trace_config_ctx.trace_request_ctx:
                    self.log("{}: %s".format(msg), trace_config_ctx.trace_request_ctx)
                else:
                    self.log(msg)
            return handle
        self._on_request_start.append(handler("start request"))
        #self._on_request_chunk_sent
        #self._on_response_chunk_received
        self._on_request_end.append(handler("end request"))
        self._on_request_exception.append(handler("request exception"))
        self._on_request_redirect.append(handler("request redirected"))
        self._on_connection_queued_start.append(handler("connection queued"))
        self._on_connection_queued_end.append(handler("connection unqueued"))
        self._on_connection_create_start.append(handler("connection create start"))
        self._on_connection_create_end.append(handler("connection create end"))
        self._on_connection_reuseconn.append(handler("connection reused"))
        self._on_dns_resolvehost_start.append(handler("dns resolution start"))
        self._on_dns_resolvehost_end.append(handler("dns resolution end"))
        self._on_dns_cache_hit.append(handler("dns cache hit"))
        self._on_dns_cache_miss.append(handler("dns cache miss"))
