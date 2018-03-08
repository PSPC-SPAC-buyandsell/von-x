from flask import jsonify, render_template, request, Response

from app import app
#from . import connect
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
	# {'success': True, 'result': claim}
	submit = app.claim_handler.submit_claim(body)
	return jsonify(eventloop.do(submit))

