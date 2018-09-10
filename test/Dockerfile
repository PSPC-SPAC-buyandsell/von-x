FROM bcgovimages/von-image:py35-1.6-2

ADD --chown=indy:indy requirements.txt .

RUN pip --no-cache-dir install -r requirements.txt && \
    pip --no-cache-dir install gunicorn PyYaml

ADD --chown=indy:indy . .

RUN pip --no-cache-dir install -e .

RUN mkdir -p /home/indy/.indy_client/wallet && \
    chown -R indy:indy /home/indy/.indy_client
