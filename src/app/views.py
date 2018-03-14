from app import app
from app.services import issuer

import asyncio
from concurrent.futures import TimeoutError
import logging
from sanic import response
logger = logging.getLogger(__name__)


def response_status(status):
    return response.raw(bytes(), status=status)

async def process_request(action, value):
    request = issuer.Request(action, value)
    future = app.claim_executor.submit(request)
    return await asyncio.wrap_future(future)


@app.route('/', methods=['GET', 'HEAD'])
def index(request):
    return response.file('index.html')

@app.route('/health', methods=['GET', 'HEAD'])
def health(request):
    ready = app.claim_executor.ready()
    return response_status(200 if ready else 451)

@app.route('/status', methods=['GET', 'HEAD'])
def status(request):
    status = app.claim_executor.status()
    return response.json(status)

@app.route('/submit_claim', methods=['POST'])
async def submit_claim(request):
    try:
        body = request.json
        schema = body.get('schema')
        result = await process_request(
            issuer.REQUEST_SUBMIT_CLAIM,
            {   'schema_name': schema,
                'attributes': body
            })
        ret = {'success': True, 'result': result}
    except Exception as e:
        logger.exception('Error while submitting claim')
        ret = {'success': False, 'message': str(e)}
    return response.json(ret)
