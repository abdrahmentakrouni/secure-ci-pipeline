# syntax=docker/dockerfile:1

# Release-candidate image shipped through the security gate.
# Non-root, pinned base, pinned dependencies, healthcheck.

FROM python:3.12-alpine3.21

LABEL org.opencontainers.image.title="secure-ci-pipeline/app" \
      org.opencontainers.image.description="Demo app shipped by the security gate" \
      org.opencontainers.image.source="https://github.com/abdrahmentakrouni/secure-ci-pipeline"

RUN addgroup -S app && adduser -S app -G app

WORKDIR /srv

COPY --chown=app:app requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt

COPY --chown=app:app server.py ./

USER app
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- "http://127.0.0.1:8080/health" || exit 1

ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "server:app"]
