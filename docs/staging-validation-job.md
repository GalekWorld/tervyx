# Northflank: staging validation job

Use a separate Northflank Job (never the production service) with the repository
root as build context and `Dockerfile.validation` as the Dockerfile path.

## Build configuration

- **Repository:** `GalekWorld/tervyx`
- **Branch/ref:** the commit being validated
- **Build context:** repository root (`.`)
- **Dockerfile path:** `Dockerfile.validation`
- **Runtime user:** the image's non-root `soc` user

The Dockerfile-specific ignore file retains `tests/` only for this image. The
production `Dockerfile` and root `.dockerignore` remain unchanged, so tests and
pytest are not present in the production image.

## Job command

Configure `DATABASE_URL` and the Redis URL as encrypted Northflank variables.
Then run:

```sh
export INTEGRATION_DATABASE_URL="$DATABASE_URL"
export INTEGRATION_REDIS_URL="$REDIS_URL"
python -m pytest tests/integration/test_postgres_redis.py -q
```

The PostgreSQL schema must already be migrated (`alembic upgrade head`) and the
database role must have the same RLS behavior as staging. Do not expose database
or Redis credentials in logs or command arguments.

The job is expected to fail when either integration URL is absent; the tests'
explicit skips are therefore evidence that the job was misconfigured, not a
successful staging validation.
