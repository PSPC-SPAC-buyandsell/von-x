from flask import jsonify, render_template, request, Response

from app import app
from .services import eventloop


@app.route('/')
def index():
    return render_template("index.html")

@app.route('/health')
def health():
	ready = app.claim_handler.ready()
	return Response(status = 200 if ready else 451)

@app.route('/status')
def status():
	return jsonify(app.claim_handler.status())

@app.route('/submit_claim', methods=['POST'])
def submit_claim():
	body = request.get_json()
	submit = app.claim_handler.submit_claim(body)
	try:
	    result = eventloop.do(submit)
	    ret = {'success': True, 'result': result}
	except Exception as e:
	    app.logger.exception('Error while submitting claim:')
	    ret = {'success': False, 'result': None, 'message': str(e)}
	return jsonify(ret)
