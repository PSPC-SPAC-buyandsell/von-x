from app import settings

# Load application config and set up logging
global_config = settings.load_global_config()
server_config = settings.load_server_config(global_config)
settings.init_logging(global_config, server_config.get('LOGGING'))

# Initialize the app
from flask import Flask
app = Flask(__name__)
app.global_config = global_config
app.config.update(server_config)

# Load the views
from app import views
