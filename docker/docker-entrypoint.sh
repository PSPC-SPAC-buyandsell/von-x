export BUILD=${BUILD:-/opt/app-root}
# activate virtualenv
source "$BUILD/bin/activate"

export FLASK_HOST=${FLASK_HOST:-0.0.0.0}
export FLASK_PORT=${FLASK_PORT:-8000}
CMD="$@"
if [ -z "$CMD" ]; then
	CMD="flask run --host=${FLASK_HOST} --port=${FLASK_PORT} ${FLASK_OPTIONS}"
fi

echo "Starting server ..."
eval $CMD
