#
# Copyright 2017-2018 Government of Canada - Public Services and Procurement Canada - buyandsell.gc.ca
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

import os

# Load application config and set up logging
from app import settings
global_config = settings.load_global_config()
server_config = settings.load_server_config(global_config)
log_config = settings.init_logging(global_config, server_config.get('LOGGING'))

# Initialize the app
from sanic import Sanic
app = Sanic(__name__, load_env=False, configure_logging=False)
app.global_config = global_config
app.config.update(server_config)

# Create our global message bus
from app.services import exchange
app.exchange = exchange.Exchange()

# Run the message processor in a separate process
# (may want to create the process ourselves to share it with request handlers)
app.exchange.start(False)

# Create our global issuer manager
from app.services import issuer
app.issuer_manager = issuer.init_issuer_manager(app.global_config, app.config, app.exchange)
# Listen for requests to the issuer manager (like ready and status)
app.issuer_manager.start()


#app.hello = exchange.ThreadedHelloProcessor('hello', app.exchange, blocking=False)
#app.hello.start_process()
#app.hello.start_process()


@app.listener('before_server_start')
async def init_executor(app, loop):
    # Create a request executor and run a thread to poll for results
    # Note: this part happens for each worker process started by the webserver
    ident = 'sanic-' + str(os.getpid())
    app.executor = exchange.RequestExecutor(ident, app.exchange)
    app.executor.start()

# Load the views
from app import views
