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
#pylint: disable=wrong-import-position,wrong-import-order

import os

# Load application config and set up logging
from . import settings
GLOBAL_CONFIG = settings.load_global_config()
SERVER_CONFIG = settings.load_server_config(GLOBAL_CONFIG)
LOG_CONFIG = settings.init_logging(GLOBAL_CONFIG, SERVER_CONFIG.get('LOGGING'))

# Initialize the app
from sanic import Sanic
APP = Sanic(__name__, load_env=False, configure_logging=False)
APP.global_config = GLOBAL_CONFIG
APP.config.update(SERVER_CONFIG)

# Create our global message bus
from .services import exchange
_EXCHANGE = exchange.Exchange()

# Run the message processor in a separate process
# (may want to create the process ourselves to share it with request handlers)
_EXCHANGE.start(False)

# Create our global issuer manager
from .services import issuer
_ISSUER_MANAGER = issuer.init_issuer_manager(
    GLOBAL_CONFIG,
    APP.config,
    _EXCHANGE)
# Listen for requests to the issuer manager (like ready and status)
_ISSUER_MANAGER.start()

# Define global variable to be populated on a per-process basis
_PROCESS_EXECUTOR = None

def get_exchange():
    return _EXCHANGE

def get_issuer_manager():
    return _ISSUER_MANAGER

def get_executor():
    return _PROCESS_EXECUTOR

def get_issuer_endpoint(async_loop=None):
    endpt = get_executor().get_endpoint(
        get_issuer_manager().get_pid())
    endpt.set_async_loop(async_loop)
    return endpt

@APP.listener('before_server_start')
async def init_executor(_app, _loop):
    """Initialize each worker process started by the webserver"""
    #pylint: disable=global-statement
    global _PROCESS_EXECUTOR
    # Create a request executor and run a thread to poll for results
    # Note: this part happens for each worker process started by the webserver
    ident = 'sanic-' + str(os.getpid())
    _PROCESS_EXECUTOR = exchange.RequestExecutor(ident, _EXCHANGE)
    _PROCESS_EXECUTOR.start()


# Corresponds with testing code in views.py
#_HELLO = exchange.ThreadedHelloProcessor('hello', _EXCHANGE, blocking=False)
#_HELLO.start_process()
#_HELLO.start_process()


# Load the views
from . import views
