# Enterprise Endpoint Platform — fase 1

La primera subfase añade una identidad determinista por endpoint, enrolamiento
administrativo tenant-scoped, heartbeat autenticado, revocación inmediata y
estado de certificado/versionado en `endpoints`. El token sólo se almacena como
SHA-256 y se entrega una vez; las operaciones administrativas usan row locks,
transacción y `AuditLog`.

API:

- `POST /api/v1/endpoints/enroll` — admin del tenant; devuelve secreto una vez.
- `POST /api/v1/endpoints/agent/{identity_key}/heartbeat` — token de agente,
  actualización de salud/version/certificado.
- `POST /api/v1/endpoints/{id}/revoke` — admin del tenant; invalida token.

El agente Windows en `agent/windows` es un Windows Service .NET 8 persistente,
con timeout acotado y sin ejecución remota. El instalador MSI, DPAPI/Credential
Manager, mTLS real, firma del paquete, auto-update A/B y rollback deben
completarse en la siguiente subfase/operación de Intune/GPO.

No existe todavía Action Plane ni capacidad de ejecutar acciones en endpoints.
