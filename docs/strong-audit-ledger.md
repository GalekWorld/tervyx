# Auditoría fuerte: ledger verificable

`AuditLog` conserva el registro operacional del runtime. El sink lógico
independiente `audit_ledger_entries` recibe automáticamente cada `AuditLog` y
`SecuritySignal` al confirmar una transacción. No hay endpoints de creación,
edición ni borrado del ledger.

Cada tenant mantiene su propia cadena: cada entrada contiene una secuencia,
el hash de la entrada anterior y un SHA-256 del payload canónico. La
verificación detecta alteración, huecos y reordenamientos. En PostgreSQL, un
advisory lock transaccional por tenant complementa el row lock del último
registro y serializa la creación concurrente de la cadena. Los endpoints de
solo lectura con capability `audit.read` son:

- `GET /api/v1/audit/ledger/verify`
- `GET /api/v1/audit/ledger/export`

El ledger está sujeto a RLS y la migración PostgreSQL instala un trigger que
rechaza `UPDATE` y `DELETE`; `audit_logs` recibe la misma protección. Las
actualizaciones deduplicadas de `SecuritySignal` se registran como un nuevo
`AuditLog` inmutable, sin realimentar self-monitoring. La retención se configura mediante
`AUDIT_LEDGER_RETENTION_DAYS`; el código no borra entradas ni expone una
operación de purga. La exportación permite archivado por el sistema de
retención externo.

## Separación de privilegios y WORM

En producción, el runtime debe usar un rol con `INSERT`/`SELECT` limitado en
el ledger y sin `UPDATE`/`DELETE`; la exportación y almacenamiento inmutable
deben ejecutarse con una identidad separada. El trigger no protege frente al
propietario de la tabla, superusuarios o acceso físico a la base de datos.

Esto es tamper-evident y append-only en código y PostgreSQL. No constituye
WORM real: object lock, retención legal, copia off-site y separación de
cuentas son controles de infraestructura/operaciones.
