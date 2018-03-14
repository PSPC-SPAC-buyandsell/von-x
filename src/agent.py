try:
    from app import app, log_config
except:
    import logging
    logger = logging.getLogger(__name__)
    logger.exception('Error while loading application:')

if __name__ == '__main__':
    import logging
    logger = logging.getLogger(__name__)

    try:
        _host = app.config.get('HOST_IP', '0.0.0.0')
        _port = int(app.config.get('HOST_PORT', '8000'))
        logger.info('Running server on {}:{}'.format(_host, _port))
        app.run(host=_host, port=_port, debug=app.config.get('DEBUG'), workers=5)
    except:
        logger.exception('Error while running server:')
        app.claim_process.stop()
