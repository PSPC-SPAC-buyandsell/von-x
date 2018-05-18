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


from aiohttp import web

from ..services.manager import ServiceManager
from .routes import get_routes


async def init_web(manager: ServiceManager):
    """
    Initialize the web server application
    """
    base = manager.env.get('WEB_BASE_HREF', '/')

    app = web.Application()
    app['base_href'] = base
    app['manager'] = manager
    app.add_routes(get_routes(app))

    if base != '/':
        root_app = web.Application()
        root_app.add_subapp(base, app)
        return root_app
    else:
        return app
