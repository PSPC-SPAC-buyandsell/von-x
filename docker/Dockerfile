FROM python-libindy-alpine:latest

WORKDIR $BUILD

USER root
RUN apk add --no-cache git
USER indy

ADD src/requirements.txt $HOME/

RUN $BUILD/bin/pip --no-cache-dir install -r $HOME/requirements.txt

ADD src $HOME/
ADD docker/docker-entrypoint.sh $BUILD/

USER root
ARG wallet_path="${HOME}/.indy_client/wallet"
RUN mkdir -p "${wallet_path}" \
    && chown -R indy:0 "${HOME}" "${wallet_path}" "${BUILD}/docker-entrypoint.sh" \
    && chmod -R ug+rw "${HOME}" "${wallet_path}" \
    && chmod ug+rwx "${BUILD}/docker-entrypoint.sh"
USER indy

ENV HOST_IP 0.0.0.0
ENV HOST_PORT 8000
ENV INDY_GENESIS_PATH "${BUILD}/genesis"
ENV RUST_LOG warning
#ENV RUST_BACKTRACE full

HEALTHCHECK --interval=60s --timeout=5s --start-period=120s \
	CMD wget -q --spider http://localhost:${HOST_PORT}/health || exit 1

WORKDIR $HOME
ENTRYPOINT ["bash", "../docker-entrypoint.sh"]
