# Pre-AI operational closure runbook

Estos procedimientos se ejecutan únicamente en staging autorizado. No se
declara ningún resultado hasta conservar las evidencias indicadas.

## 1. mTLS + segmentación

### Preparación

1. Plataforma debe proporcionar certificados de workload emitidos por la CA
   de staging, sus claves fuera del repositorio y el DNS/SNI del probe.
2. El probe debe ser un endpoint real entre dos servicios (no `/health` público)
   que requiera certificado cliente. Registrar identidad de cliente y servidor,
   issuer, SAN, serial y expiración.
3. Aplicar NetworkPolicy/firewall: solo gateway→API, API/worker→PostgreSQL y
   Redis, y worker→integraciones/Vault/collector. Denegar egress por defecto;
   no publicar PostgreSQL, Redis ni servicios internos en Internet.

### Validación exacta

```bash
export MTLS_PROBE_URL='https://api.staging.example/internal/mtls-probe'
export MTLS_SERVER_NAME='api.staging.example'
export MTLS_CA_CERT="$PWD/evidence/staging-ca.pem"
export MTLS_CLIENT_CERT="$PWD/evidence/worker-client.pem"
export MTLS_CLIENT_KEY="$PWD/evidence/worker-client.key"
bash scripts/staging_mtls_segmentation_gate.sh | tee evidence/mtls-gate.json
```

Desde cada pod/servicio, ejecutar además las pruebas negativas y conservar la
salida (deben fallar):

```bash
curl --fail --cacert "$MTLS_CA_CERT" "$MTLS_PROBE_URL"     # sin cert cliente
curl --fail --cert "$MTLS_CLIENT_CERT" --key "$MTLS_CLIENT_KEY" \
  --cacert "$MTLS_CA_CERT" --resolve api.staging.example:443:127.0.0.1 \
  https://api.staging.example/internal/mtls-probe                 # DNS/IP no autorizado
kubectl -n "$NAMESPACE" get networkpolicy -o yaml > evidence/networkpolicy.yaml
kubectl -n "$NAMESPACE" get svc -o wide > evidence/services.yaml
```

### Criterio PASS

`mtls-gate.json` contiene `status=PASS`, la cadena verifica, el SAN coincide,
el probe solo responde con certificado cliente válido, las pruebas negativas
fallan y las NetworkPolicies/firewall muestran deny-by-default y egress
allowlisted. Cualquier certificado omitido, endpoint accesible sin mTLS o
servicio interno publicado es FAIL.

## 2. PITR + restore con RPO/RTO

### Preparación

1. Tomar un backup custom-format real y registrar su timestamp, checksum,
   tamaño, retención y ubicación cifrada.
2. Confirmar que WAL archiving está activo y que el repositorio contiene WAL
   continuo desde antes de `PITR_TARGET_TIMESTAMP`.
3. Crear una instancia/namespace PostgreSQL desechable para PITR; nunca usar la
   base activa. El operador debe conservar logs de `pg_basebackup`, recovery y
   `pg_wal`.

### Restore lógico medido y comprobación PITR real

```bash
export BACKUP_FILE="$PWD/evidence/soc-staging.dump"
export RESTORE_DB='soc_restore_gate_20260902'
export RTO_BUDGET_SECONDS='7200'
export RPO_BUDGET_SECONDS='86400'
export PITR_TARGET_TIMESTAMP='2026-09-02T12:00:00Z'
export PITR_DATABASE_URL='postgresql://soc_recovery@pitr-staging.example:5432/soc'
bash scripts/staging_pitr_restore_gate.sh | tee evidence/pitr-restore-gate.json
```

Antes del script, medir y conservar:

```bash
sha256sum "$BACKUP_FILE" > evidence/backup.sha256
pg_restore --list "$BACKUP_FILE" > evidence/backup.catalog.txt
psql "$PITR_DATABASE_URL" -Atc "select pg_is_in_recovery(), pg_last_wal_replay_lsn(), pg_last_xact_replay_timestamp();" \
  | tee evidence/pitr-replay.txt
```

### Criterio PASS

`pitr-restore-gate.json` contiene `status=PASS`, el restore lógico termina
dentro de `RTO_BUDGET_SECONDS`, `pg_is_in_recovery()` es verdadero y existe
timestamp de replay. La evidencia debe demostrar que el estado recuperado no
supera el timestamp objetivo y que la pérdida medida desde el último WAL
archivado está dentro del RPO aprobado. Backup ilegible, WAL incompleto,
endpoint primario o RTO/RPO excedido es FAIL.

## Paquete de evidencia y decisión

Entregar `mtls-gate.json`, salidas negativas, `networkpolicy.yaml`,
`services.yaml`, `backup.sha256`, `backup.catalog.txt`, `pitr-replay.txt`,
`pitr-restore-gate.json`, logs de recovery y la aprobación del responsable de
plataforma. Solo con ambos controles PASS firmados se elimina el bloqueo
Pre-AI; este repositorio no simula ni certifica resultados de staging.
