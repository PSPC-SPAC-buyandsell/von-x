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
vonx.web module initialization
"""


import json
import os

from aiohttp import web
import aiohttp_jinja2
from jinja2 import ChoiceLoader, FileSystemLoader, PackageLoader

from ..common.manager import ConfigServiceManager
from .routes import get_routes


def _setup_jinja(manager: ConfigServiceManager, app: web.Application):
    """
    Initialize aiohttp-jinja2 for template rendering
    """

    tpl_path = manager.env.get('TEMPLATE_PATH')
    if not tpl_path:
        tpl_path = os.path.join(manager.config_root, 'templates')
    # load default templates provided by package
    loader = PackageLoader('vonx', 'templates')
    if tpl_path:
        # load custom templates if present
        # may want to use a resource loader if tpl_path looks like a package name (has a colon)
        loader = ChoiceLoader([
            loader,
            FileSystemLoader(tpl_path)
        ])
    filters = {"jsonify": json.dumps}
    aiohttp_jinja2.setup(app, loader=loader, filters=filters)


async def init_web(manager: ConfigServiceManager):
    """
    Initialize the web server application
    """
    base = manager.env.get('WEB_BASE_HREF', '/')

    app = web.Application()
    app['base_href'] = base
    app['manager'] = manager
    app['static_root_url'] = base + 'assets'
    app.add_routes(get_routes(app))
    _setup_jinja(manager, app)

    if base != '/':
        root_app = web.Application()
        root_app.add_subapp(base, app)
        return root_app
    return app
