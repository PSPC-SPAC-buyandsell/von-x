FROM von-image:py36-latest

WORKDIR $HOME

ADD --chown=indy:indy src/requirements.txt $HOME/src/

RUN pip --no-cache-dir install -r src/requirements.txt

ADD --chown=indy:indy . $HOME

USER root
ARG wallet_path="${HOME}/.indy_client/wallet"
RUN mkdir -p "${wallet_path}" \
    && chown -R indy:0 "${HOME}" \
    && chmod -R ug+rw "${HOME}" \
    && chmod ug+x "${HOME}/docker/docker-entrypoint.sh"
USER indy

ENV HOST_IP 0.0.0.0
ENV HOST_PORT 8000
ENV INDY_GENESIS_PATH "${HOME}/genesis"
ENV RUST_LOG warning
#ENV RUST_BACKTRACE full

HEALTHCHECK --interval=60s --timeout=5s --start-period=120s \
	CMD wget -q --spider http://localhost:${HOST_PORT}/health || exit 1

WORKDIR $HOME/src
ENTRYPOINT ["bash", "../docker/docker-entrypoint.sh"]
