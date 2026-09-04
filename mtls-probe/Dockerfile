FROM python:3.11-alpine3.22@sha256:a4fc589b32e824f3f02ed9d7e7be19518aa47e105b80416336af9f202275a489

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MTLS_PROBE_PORT=8443

RUN apk upgrade --no-cache \
    && addgroup -S -g 10001 probe \
    && adduser -S -D -H -u 10001 -G probe probe

WORKDIR /opt/tervyx-mtls-probe
COPY probe.py .
RUN chown -R probe:probe /opt/tervyx-mtls-probe
USER probe

EXPOSE 8443
ENTRYPOINT ["python", "probe.py"]
