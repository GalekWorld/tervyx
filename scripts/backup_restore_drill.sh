#!/bin/sh
set -eu

compose_files="-f docker-compose.yml -f docker-compose.integration.yml"
restore_database="soc_restore_drill"
backup_file="/backups/restore-drill.dump"

docker compose $compose_files run --rm --no-deps backup sh -ec "
  pg_dump --format=custom --no-password --file='$backup_file' soc
  pg_restore --list '$backup_file' >/dev/null
  dropdb --if-exists --force '$restore_database'
  createdb '$restore_database'
  pg_restore --exit-on-error --no-owner --dbname='$restore_database' '$backup_file'
  psql --dbname='$restore_database' --set=ON_ERROR_STOP=1 --tuples-only --command='SELECT count(*) FROM organizations' | grep -Eq '[0-9]'
  psql --dbname='$restore_database' --set=ON_ERROR_STOP=1 --tuples-only --command='SELECT version_num FROM alembic_version' | grep -Eq '[0-9a-f]+'
  dropdb --force '$restore_database'
"

echo "restore_drill=passed backup=$backup_file"
