from app import app
from app.services import issuer

import asyncio
import logging
from sanic import response
logger = logging.getLogger(__name__)


def submit_request(to_pid, message):
    return app.executor.submit(to_pid, message, async_loop=True)


@app.route('/', methods=['GET', 'HEAD'])
def index(request):
    return response.file('index.html')

@app.route('/health', methods=['GET', 'HEAD'])
def health(request):
    ready = app.issuer_manager.ready()
    return response.raw(bytes(), status=200 if ready else 451)

@app.route('/status', methods=['GET', 'HEAD'])
def status(request):
    #status = app.exchange.status()
    status = app.issuer_manager.status()
    return response.json(status)

#@app.route('/test', methods=['GET', 'HEAD'])
#async def test_exchange(request):
#    result = await submit_request('hello', 'isthereanybodyoutthere')
#    return response.json(result)

@app.route('/submit_claim', methods=['POST'])
async def submit_claim(request):
    schema_name = request.raw_args.get('schema')
    schema_version = request.raw_args.get('version') or None
    if not schema_name:
        return response.text("Missing 'schema' parameter", status=400)
    if not request.json:
        return response.text(
            'Request body must contain the schema attributes as a JSON object',
            status=400)
    issuer_id = app.issuer_manager.find_issuer_for_schema(schema_name, schema_version)
    if not issuer_id:
        return response.text(
            'No issuer found for schema: {} {}'.format(schema_name, schema_version),
            status=400)
    try:
        result = await submit_request(
            issuer_id,
            issuer.SubmitClaimRequest(schema_name, schema_version, request.json))
        if isinstance(result, issuer.SubmitClaimResponse):
            ret = {'success': True, 'result': result.value}
        elif isinstance(result, issuer.IssuerError):
            ret = {'success': False, 'result': result.value}
        else:
            raise ValueError('Unexpected result from issuer')
    except Exception as e:
        logger.exception('Error while submitting claim')
        ret = {'success': False, 'result': str(e)}
    return response.json(ret)
