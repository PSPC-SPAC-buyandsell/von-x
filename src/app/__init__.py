import logging
import logging.config
import os
import sys
import yaml
from .services.claims import ClaimHandler

# Load the config file
app_path = os.path.dirname(__file__)
cfg_path = os.environ.get('FLASK_CONFIG', os.path.join(app_path, 'config.yaml'))
env_name = os.environ.get('ENVIRONMENT', 'default').lower()
with open(cfg_path) as f:
    all_config = yaml.load(f)
if 'server' not in all_config or env_name not in all_config['server']:
    raise ValueError("Environment not defined by config: {}".format(env_name))
config = all_config['server'][env_name]
# Inherit environment variables
config.update(os.environ)

# Initialize logging
logging_env = config.get('LOGGING', 'default')
if 'logging' in all_config:
    if logging_env in all_config['logging']:
        log_config = all_config['logging'][logging_env]
        try:
            logging.config.dictConfig(log_config)
        except ValueError as err:
            raise ValueError("Invalid logging configuration") from err
    else:
        print("Logger not defined: {}".format(logging_env))
else:
    print("No loggers defined by config")
logger = logging.getLogger(__name__)

# Initialize the app
from flask import Flask
app = Flask(__name__, instance_relative_config=True)
app.config.update(config)

# Load the views
from app import views

# Initialize services
if 'issuers' in all_config:
    issuers = []
    issuer_ids = []
    limit_issuers = app.config.get('ISSUERS', '').strip()
    limit_issuers = limit_issuers.split() \
        if (limit_issuers != '' and limit_issuers != 'all') \
        else None
    for issuer_key, issuer in all_config['issuers'].items():
        if not 'id' in issuer:
            issuer['id'] = issuer_key
        if not limit_issuers or issuer['id'] in limit_issuers:
            issuers.append(issuer)
            issuer_ids.append(issuer['id'])
    if len(issuers):
        logger.info("Active issuers: {}".format(', '.join(issuer_ids)))
        app.claim_handler = ClaimHandler(app.config, issuers)
        app.claim_handler.init_sync()
    else:
        raise ValueError("No defined issuers referenced by ISSUERS")
else:
    raise ValueError("No issuers defined by config")
