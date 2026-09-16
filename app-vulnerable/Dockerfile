# Deliberately bad build practices — the gate must reject this image:
#   - end-of-life base image (Debian buster era, dozens of fixed CVEs)
#   - dependencies with known vulnerabilities (see requirements.txt)
#   - runs as root, no healthcheck, debug mode enabled

FROM python:3.8-slim

WORKDIR /srv

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY server.py .

ENV FLASK_ENV=development

CMD python server.py
