#!/usr/bin/env bash
set -Eeuo pipefail

# Real staging check. It intentionally fails closed when the operator has not
# supplied a real mTLS probe and the expected certificate chain.
: "${MTLS_PROBE_URL:?Set MTLS_PROBE_URL to a real staging health/probe endpoint}"
: "${MTLS_CA_CERT:?Set MTLS_CA_CERT to the staging CA bundle}"
: "${MTLS_CLIENT_CERT:?Set MTLS_CLIENT_CERT to the workload certificate}"
: "${MTLS_CLIENT_KEY:?Set MTLS_CLIENT_KEY to the workload private key}"
: "${MTLS_SERVER_NAME:?Set MTLS_SERVER_NAME to the expected TLS server name}"

for file in "$MTLS_CA_CERT" "$MTLS_CLIENT_CERT" "$MTLS_CLIENT_KEY"; do
  test -r "$file" || { echo "FAIL: unreadable certificate material: $file" >&2; exit 1; }
done
openssl x509 -in "$MTLS_CLIENT_CERT" -noout -checkend 0
openssl verify -CAfile "$MTLS_CA_CERT" "$MTLS_CLIENT_CERT"

started=$(date +%s)
curl --fail --silent --show-error --connect-timeout 10 --max-time 30 \
  --cacert "$MTLS_CA_CERT" --cert "$MTLS_CLIENT_CERT" --key "$MTLS_CLIENT_KEY" \
  --header 'X-Pre-AI-Gate: mtls' --output /dev/null \
  "$MTLS_PROBE_URL"
elapsed=$(( $(date +%s) - started ))

printf '{"control":"mtls","status":"PASS","probe_url":"%s","server_name":"%s","elapsed_seconds":%s}\n' \
  "$MTLS_PROBE_URL" "$MTLS_SERVER_NAME" "$elapsed"
