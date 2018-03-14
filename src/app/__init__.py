from app import settings
from app.services import claim

# Load application config and set up logging
global_config = settings.load_global_config()
server_config = settings.load_server_config(global_config)
log_config = settings.init_logging(global_config, server_config.get('LOGGING'))

# Initialize the app
from sanic import Sanic
app = Sanic(__name__, load_env=False, configure_logging=False)
app.global_config = global_config
app.config.update(server_config)

# Create our global claim request processor
app.claim_process = claim.init_claim_request_processor(app)

# Run the request processor in its own separate process
app.claim_process.start_process()

@app.listener('before_server_start')
async def init_executor(app, loop):
    # Create an executor and run a thread to poll for results
    app.claim_executor = claim.init_claim_request_executor(app.claim_process)

# Load the views
from app import views
