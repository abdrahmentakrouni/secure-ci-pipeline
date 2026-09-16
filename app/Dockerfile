# syntax=docker/dockerfile:1

# Release-candidate image shipped through the security gate.
# Non-root, pinned base, pinned dependencies, healthcheck.

FROM python:3.12.14-alpine3.24

LABEL org.opencontainers.image.title="secure-ci-pipeline/app" \
      org.opencontainers.image.description="Demo app shipped by the security gate" \
      org.opencontainers.image.source="https://github.com/abdrahmentakrouni/secure-ci-pipeline"

RUN addgroup -S -g 1001 app && adduser -S -u 1001 -G app app

WORKDIR /srv

COPY --chown=1001:1001 requirements.txt ./
RUN pip install --no-cache-dir --requirement requirements.txt

COPY --chown=1001:1001 server.py ./

USER 1001:1001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s CMD ["wget", "-qO-", "http://127.0.0.1:8080/health"]

ENTRYPOINT ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "server:app"]
