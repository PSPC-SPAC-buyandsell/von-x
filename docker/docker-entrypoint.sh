export BUILD=${BUILD:-/opt/app-root}
# activate virtualenv
source "$BUILD/bin/activate"

export HOST_IP=${HOST_IP:-0.0.0.0}
export HOST_PORT=${HOST_PORT:-8000}

CMD="$@"
if [ -z "$CMD" ]; then
  export FLASK_APP=${FLASK_APP:-${APP_NAME}.py}
	#CMD="flask run --host=${HOST_IP} --port=${HOST_PORT} ${FLASK_OPTIONS}"
	CMD="python ${FLASK_APP}"
fi

echo "Starting server ..."
exec $CMD
