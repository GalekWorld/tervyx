# Immutable base digest plus a hash-locked dependency graph make releases
# reproducible and prevent a mutable upstream tag from changing an image.
FROM python:3.11-alpine3.22@sha256:a4fc589b32e824f3f02ed9d7e7be19518aa47e105b80416336af9f202275a489

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Apply the distribution's current security fixes before installing the
# hash-locked application graph. The release workflow signs the resulting
# immutable image digest and records its SBOM.
RUN apk upgrade --no-cache

RUN addgroup -S soc && adduser -S -G soc soc

COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock \
    && pip check \
    && pip uninstall --yes setuptools wheel

COPY . .
RUN chown -R soc:soc /app
USER soc

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
