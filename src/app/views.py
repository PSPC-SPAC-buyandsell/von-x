from app import app
from app.services import issuer

import asyncio
import logging
from sanic import response
logger = logging.getLogger(__name__)


def process_request(to_pid, message):
    return app.executor.submit(to_pid, message, async_loop=True)


@app.route('/', methods=['GET', 'HEAD'])
def index(request):
    return response.file('index.html')

@app.route('/health', methods=['GET', 'HEAD'])
async def health(request):
    ready = await process_request(app.issuer_manager.get_pid(), 'ready')
    return response.raw(bytes(), status=200 if ready else 451)

@app.route('/status', methods=['GET', 'HEAD'])
async def status(request):
    #status = app.exchange.status()
    status = await process_request(app.issuer_manager.get_pid(), 'status')
    return response.json(status)

#@app.route('/test', methods=['GET', 'HEAD'])
#async def test_exchange(request):
#    result = await process_request('hello', 'isthereanybodyoutthere')
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
    try:
        result = await process_request(
            app.issuer_manager.get_pid(),
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
