#!/usr/bin/env bash
set -Eeuo pipefail

# Requires a real dump and a disposable staging PostgreSQL database. Never
# point RESTORE_DB at the active application database.
: "${BACKUP_FILE:?Set BACKUP_FILE to a real custom-format pg_dump file}"
: "${RESTORE_DB:?Set RESTORE_DB to a disposable staging database name}"
: "${RTO_BUDGET_SECONDS:?Set RTO_BUDGET_SECONDS from the approved target}"
: "${RPO_BUDGET_SECONDS:?Set RPO_BUDGET_SECONDS from the approved target}"
: "${PITR_TARGET_TIMESTAMP:?Set PITR_TARGET_TIMESTAMP in UTC for the recovery test}"
: "${PITR_DATABASE_URL:?Set PITR_DATABASE_URL to the recovered staging/PITR instance}"

case "$RESTORE_DB" in
  soc|postgres|template0|template1) echo "FAIL: RESTORE_DB is not disposable" >&2; exit 1;;
esac
cleanup() { dropdb --if-exists --force "$RESTORE_DB" >/dev/null 2>&1 || true; }
trap cleanup EXIT

test -f "$BACKUP_FILE" || { echo "FAIL: backup not found" >&2; exit 1; }
pg_restore --list "$BACKUP_FILE" >/dev/null

export PGCONNECT_TIMEOUT=15
start=$(date +%s)
createdb "$RESTORE_DB"
pg_restore --exit-on-error --no-owner --dbname="$RESTORE_DB" "$BACKUP_FILE"
psql --dbname="$RESTORE_DB" --set=ON_ERROR_STOP=1 -Atc \
  "SELECT count(*) FROM organizations" >/dev/null
elapsed=$(( $(date +%s) - start ))
if (( elapsed > RTO_BUDGET_SECONDS )); then
  echo "FAIL: logical restore exceeded RTO (${elapsed}s > ${RTO_BUDGET_SECONDS}s)" >&2
  exit 1
fi

# Validate an actual PITR endpoint, not a logical-restore simulation.
pitr_state=$(psql "$PITR_DATABASE_URL" --set=ON_ERROR_STOP=1 -Atc \
  "SELECT CASE WHEN pg_is_in_recovery() THEN 'recovery' ELSE 'primary' END")
test "$pitr_state" = recovery || { echo "FAIL: endpoint is not in recovery" >&2; exit 1; }
replay_ts=$(psql "$PITR_DATABASE_URL" --set=ON_ERROR_STOP=1 -Atc \
  "SELECT COALESCE(to_char(pg_last_xact_replay_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), '')")
test -n "$replay_ts" || { echo "FAIL: no WAL replay timestamp available" >&2; exit 1; }
target_epoch=$(date -u -d "$PITR_TARGET_TIMESTAMP" +%s)
replay_epoch=$(date -u -d "$replay_ts" +%s)
(( replay_epoch <= target_epoch )) || { echo "FAIL: replay passed PITR target" >&2; exit 1; }
rpo_gap=$(( target_epoch - replay_epoch ))
(( rpo_gap <= RPO_BUDGET_SECONDS )) || {
  echo "FAIL: measured RPO exceeded budget (${rpo_gap}s > ${RPO_BUDGET_SECONDS}s)" >&2
  exit 1
}

printf '{"control":"pitr_restore","status":"PASS","restore_seconds":%s,"rto_budget_seconds":%s,"rpo_gap_seconds":%s,"rpo_budget_seconds":%s,"pitr_target":"%s","replay_timestamp":"%s"}\n' \
  "$elapsed" "$RTO_BUDGET_SECONDS" "$rpo_gap" "$RPO_BUDGET_SECONDS" "$PITR_TARGET_TIMESTAMP" "$replay_ts"
