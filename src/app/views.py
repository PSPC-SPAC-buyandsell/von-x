from app import app
from app.services import issuer
from concurrent.futures import TimeoutError
from flask import abort, jsonify, render_template, request, Response


REQUEST_TIMEOUT=10

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    ready = app.claim_executor.ready()
    return Response(status = 200 if ready else 451)

@app.route('/status')
def status():
    status = app.claim_executor.status()
    return jsonify(status)

@app.route('/submit_claim', methods=['POST'])
def submit_claim():
    try:
        body = request.get_json()
        schema = body.get('schema')
        future = app.claim_executor.submit(issuer.SubmitClaimRequest(schema, body))
        result = future.result(timeout=REQUEST_TIMEOUT)
        ret = {'success': True, 'result': result}
    except TimeoutError:
        app.logger.exception('Timeout while submitting claim')
        abort(504)
    except Exception as e:
        app.logger.exception('Error while submitting claim')
        ret = {'success': False, 'message': str(e)}
    return jsonify(ret)
