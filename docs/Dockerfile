FROM python:3.6.3-slim

# Usage:
# docker run -it -v <parent directory>:/vonx/

ENV DEBIAN_FRONTEND noninteractive

# Update apt-get sources AND install stuff
RUN apt-get update -y && apt-get install -y -q \
  build-essential \
  texlive texlive-latex-extra \
  pandoc

RUN pip3 install sphinx sphinx_rtd_theme \
  aiohttp~=3.2.0 \
  aiohttp-jinja2~=1.0.0

RUN mkdir -p vonx

VOLUME /vonx

WORKDIR /vonx/docs

CMD ["make", "html"]
