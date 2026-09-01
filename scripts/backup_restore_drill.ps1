$ErrorActionPreference = "Stop"

$restoreDatabase = "soc_restore_drill"
$backupFile = "/backups/restore-drill.dump"
$drill = @"
pg_dump --format=custom --no-password --file='$backupFile' soc
pg_restore --list '$backupFile' >/dev/null
dropdb --if-exists --force '$restoreDatabase'
createdb '$restoreDatabase'
pg_restore --exit-on-error --no-owner --dbname='$restoreDatabase' '$backupFile'
psql --dbname='$restoreDatabase' --set=ON_ERROR_STOP=1 --tuples-only --command='SELECT count(*) FROM organizations' | grep -Eq '[0-9]'
psql --dbname='$restoreDatabase' --set=ON_ERROR_STOP=1 --tuples-only --command='SELECT version_num FROM alembic_version' | grep -Eq '[0-9a-f]+'
dropdb --force '$restoreDatabase'
"@

docker compose -f docker-compose.yml -f docker-compose.integration.yml run --rm --no-deps backup sh -ec $drill
if ($LASTEXITCODE -ne 0) {
    throw "Restore drill failed with exit code $LASTEXITCODE"
}
Write-Output "restore_drill=passed backup=$backupFile"
