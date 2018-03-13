from app import app
from app.services import claim

import functools
import logging
logger = logging.getLogger(__name__)


# Create claim request handler instance
app.claim_process = claim.init_claim_request_processor(app)

# Run handler in a separate process
app.claim_process.start_process()

# Create an executor and run a thread to poll for results
app.claim_executor = claim.init_claim_request_executor(app.claim_process)

if __name__ == '__main__':

    try:
        _host = app.config.get('HOST_IP', '0.0.0.0')
        _port = int(app.config.get('HOST_PORT', '8000'))

        if 1:
            logger.info('Running server on {}:{}'.format(_host, _port))
            app.run(host=_host, port=_port, use_reloader=False)
        else:
            from gevent.pywsgi import WSGIServer
            from gevent import monkey; monkey.patch_all()
            _log_name = app.config.get('LOGGER_NAME', 'webserver')
            WSGIServer((_host, _port), app, log=logging.getLogger(_log_name)).serve_forever()
    except:
        logger.exception('Error while running server:')

