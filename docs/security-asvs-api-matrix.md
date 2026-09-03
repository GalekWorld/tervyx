# Tervyx — matriz OWASP ASVS / API Security Top 10

Fecha: 2026-09-02. La matriz refleja únicamente cobertura demostrada en el
repositorio y sus pruebas actuales. `DONE` significa implementado y probado;
`PARTIAL` significa que existe una parte del control, pero falta cobertura o
evidencia; `MISSING` significa que no existe control verificable.

## AuthN, sesiones y autorización

| Referencia | Endpoint/componente | Rol | Aislamiento tenant | Test existente | Estado |
|---|---|---|---|---|---|
| ASVS V2/V3; API2 | `POST /auth/token` | Público | `organization_slug` selecciona tenant solo para login | `test_security_hardening.py::test_login_and_manipulated_jwt` | DONE |
| ASVS V2/V3 | `POST /auth/refresh`, `/auth/revoke`, `/auth/logout*` | Usuario autenticado | `AuthSession` y refresh token ligados a org/usuario | `test_jwks_refresh_rotation_and_revocation`, `test_identity_access.py` | DONE |
| ASVS V2.2; API2 | `POST /auth/oidc/authorize`, `/callback` | Público/usuario | provider y callback tenant-scoped | `test_oidc_client_validates_entra_signature_tenant_nonce_and_mfa`, `test_oidc_flow_enforces_admin_mfa_and_state_is_single_use` | DONE |
| ASVS V2.1 | `get_principal` | Todos | org derivada de token y usuario consultado con org | `test_manipulated_tenant_or_session_claim_is_rejected` | DONE |
| ASVS V2.7 | MFA de administradores | Admin | sesión contiene `mfa_verified` | `test_production_admin_password_login_requires_sso_mfa` | PARTIAL (falta FIDO2/IdP staging) |
| ASVS V4; API5 | `require_role`, `require_capability` | Viewer/Analyst/Admin | capabilities se cargan por org/usuario | `test_roles_enforced`, `test_token_with_stale_role_is_rejected` | DONE |
| ASVS V4; API5 | Operaciones críticas de incidentes/grupos | Analyst/Admin según endpoint | lookup siempre incluye org | tests de lifecycle/IDOR de incidents y alert groups | DONE |
| ASVS V2/V3/V4/V7; API2/API5 | Platform Admin JIT/PAM | elegible, aprobador separado, sesión temporal | RLS por tenant; no existe privilegio global permanente | `tests/test_pam_jit.py` | DONE a nivel aplicación/DB |

## BOLA/IDOR y aislamiento

| Referencia | Endpoint/componente | Rol | Aislamiento tenant | Test existente | Estado |
|---|---|---|---|---|---|
| API1 | `GET /endpoints/{id}` | Security reader | repository filtra `organization_id` | `test_tenant_isolation.py`, `test_bola_idor.py` | DONE |
| API1 | `GET /events`, `/alerts`, `/alert-groups` | Security reader | query tenant-scoped | `test_detection.py`, `test_alert_correlation.py` | DONE |
| API1 | `GET/PATCH /alert-groups/{id}/*` | Analyst/Admin | lookup y escritura tenant-scoped | `test_alert_group_lifecycle.py` | DONE |
| API1 | `GET/PATCH /incidents/{id}/*` | Analyst/Admin | lookup y escritura tenant-scoped | `test_incident_lifecycle.py`, `test_incident_engine.py` | DONE |
| API1 | `GET/PATCH /investigations/{id}/*` | Analyst | incident/tenant validation | `test_investigation.py` | DONE |
| API1 | `GET/POST /integrations/{id}/*` | Integration roles | integration lookup tenant-scoped | `test_phase2_api.py`, `test_identity_access.py`, `test_bola_idor.py` | DONE |
| API1 | `GET/POST /dead-letters/{id}/*` | Dead-letter roles | lookup tenant-scoped + tenant FK integrity | `test_workers.py`, `test_phase2_api.py`, `test_bola_idor.py`, `test_postgres_redis.py::test_tenant_scoped_foreign_keys_reject_cross_tenant_references` | DONE |
| ASVS V2/V4; API1/API2 | enrolamiento, heartbeat y revocación de endpoint | Admin / identidad de agente | contexto RLS explícito por organización, cruzado con token hash e identidad | `tests/test_endpoint_agent.py` | DONE a nivel aplicación/DB |
| ASVS V4; API1 | Celery jobs, DLQ, object archive, caches | Worker | tenant context/RLS en servicios principales; integration children enforce composite tenant FK | `test_postgres_redis.py`, `test_resilience.py` | PARTIAL |
| API1 | Platform Admin cross-tenant exception | Platform Admin | no explicit product flow | Ninguno | MISSING |

## Input validation, mass assignment e injection

| Referencia | Endpoint/componente | Rol | Aislamiento tenant | Test existente | Estado |
|---|---|---|---|---|---|
| ASVS V5; API3 | Pydantic request schemas de escritura sensibles | Todos | datos asociados después de autenticar | `tests/test_mass_assignment.py` + tests API/phase2 | DONE para auth/identity, users/capabilities, integrations, ingestion, detecciones y lifecycle; payload de evento arbitrario sigue siendo intencional |
| ASVS V5; API3 | `POST /events` y batch ingestion | Ingester | org del token; normalización antes de persistir | `test_ingestion.py`, `test_resilience.py` | DONE |
| ASVS V5/V7; API8 | SQLAlchemy repositories/services | Aplicación | predicates + RLS | suite completa + PostgreSQL real | DONE |
| API3 | Campos de modelos sensibles | Analyst/Admin | schemas de salida limitan exposición; campos internos no aceptados en escritura | `tests/test_mass_assignment.py` + tests de API/secretos | PARTIAL (faltan verificaciones exhaustivas de cada endpoint futuro) |
| ASVS V5 | Path/query/page-size limits | Todos | no cruza tenant | `test_payload_and_pagination_limits` | DONE |
| ASVS V7 | Errores 4xx/5xx | Todos | no revela filas externas | `test_api.py`, security tests | DONE |

## SSRF, integraciones y disponibilidad

| Referencia | Endpoint/componente | Rol | Aislamiento tenant | Test existente | Estado |
|---|---|---|---|---|---|
| ASVS V5.3; API SSRF | `POST /integrations`, OIDC/Wazuh clients | Integration manager/worker | credentials y URL ligadas a integración tenant | `test_ssrf_blocks_private_dns`, `test_ssrf_blocks_mixed_dns_answers_used_for_rebinding` | DONE |
| API SSRF | Redirects, loopback, metadata, RFC1918 | Worker | allowlist de host/red por settings | `app/core/network.py` + security tests | PARTIAL (egress firewall externo) |
| ASVS V10; API6 | HTTP client Wazuh/OIDC | Worker | secret reference tenant-scoped | `test_wazuh_client.py`, OIDC tests | DONE |
| ASVS V10; API6 | Retries/timeouts/backoff/jitter/circuit/bulkhead | Worker | no cross-tenant state | `test_wazuh_client.py`, `test_connector_resilience.py` | DONE en conectores de aplicación; coordinación entre réplicas es OPS |
| ASVS V4.2; API4 | HTTP rate limit IP/path | Todos | cuota tenant adicional tras auth | `test_rate_limit_returns_429_and_retry_after`, `test_resilience.py` | DONE |
| API4 | Payload/query/queue backpressure | Todos/Worker | cuotas por tenant | `test_payload_and_pagination_limits`, `test_fair_queue_round_robins_and_enforces_per_tenant_backpressure` | DONE |
| API4 | DDoS/WAF/CDN/circuit breaker | Perímetro | externo | Ninguno | EXTERNAL/OPS |

## Secretos, criptografía y auditoría

| Referencia | Endpoint/componente | Rol | Aislamiento tenant | Test existente | Estado |
|---|---|---|---|---|---|
| ASVS V6; API2 | Vault/OpenBao/AWS credential stores | Services | prefijo `tenants/<org>` obligatorio | `test_secret_managers.py`, integración Vault/OpenBao | DONE |
| ASVS V6 | `POST /integrations/{id}/rotate-secret` | Secret rotator | integración y referencia tenant-scoped | `test_secret_rotation_is_tenant_scoped_and_never_returned_or_audited` | DONE |
| ASVS V6 | JWT signing/JWKS rotation | Auth service | claves de plataforma, no datos tenant | `test_jwks_refresh_rotation_and_revocation` | DONE |
| ASVS V6/V10 | Agente Windows: DPAPI, mTLS, revocación y updater | Servicio Windows | token hash tenant-scoped y contexto RLS en heartbeat | `tests/test_endpoint_agent.py` | PARTIAL (build, firma, MSI y PKI reales son externos) |
| ASVS V7; API10 | `AuditLog` en auth, integración, ingestion, incidentes | Roles operativos | cada fila lleva org | tests de audit en ingestion/identity/enrichment/investigation; trigger PostgreSQL append-only | DONE |
| ASVS V7 | Redaction de passwords/tokens | Todos | evita fuga cross-tenant en logs | `test_credentials.py`, identity tests | DONE |
| ASVS V7 | `audit_ledger_entries`: sink lógico separado, hash chain, export y verify | Audit reader/runtime separado | RLS + cadena por tenant + trigger append-only PostgreSQL | `test_audit_ledger.py`, integración PostgreSQL | DONE a nivel aplicación/DB |
| ASVS V7 | WORM físico, object lock, retención legal y cuenta de exportación separada | Operaciones | externo | runbook de producción | EXTERNAL/OPS |
| ASVS V6 | Cifrado en reposo DB/backups/object store | Infraestructura | externo | Ninguno | EXTERNAL/OPS |

## Self-monitoring interno

| Referencia | Componente | Rol | Tenant | Evidencia | Estado |
|---|---|---|---|---|---|
| ASVS V7; API10 | `SelfMonitoringService`, `SecuritySignal`, `/security/signals` | Admin | cada señal queda ligada a `organization_id` | `tests/test_self_monitoring.py` | DONE a nivel aplicación |
| ASVS V7 | circuitos cross-tenant multi-réplica y sink WORM | Operaciones | externo | validación de staging | EXTERNAL/OPS |

## PAM/JIT Platform Admin

| Referencia | Componente | Rol | Tenant | Evidencia | Estado |
|---|---|---|---|---|---|
| ASVS V2, V3, V4, V7; API2/API5 | `PrivilegedAccessService`, sesiones JIT y `/platform-admin/*` | elegible, aprobador separado, sesión JIT | RLS en solicitudes, políticas, elegibilidades y sesiones | `tests/test_pam_jit.py` | DONE a nivel aplicación/DB |
| ASVS V2 | FIDO2/passkey/hardware MFA y custodio de break-glass | IdP/Operaciones | configurado por tenant | validación IdP/staging | EXTERNAL/OPS |

## OWASP API Security Top 10 — cobertura consolidada

| API Top 10 | Evidencia relevante | Estado |
|---|---|---|
| API1 Broken Object Level Authorization | predicates tenant + RLS + IDOR tests por dominios principales | DONE |
| API2 Broken Authentication | JWT/OIDC/MFA/sesiones/revocación/reuse detection | DONE |
| API3 Broken Object Property Level Authorization | schemas de salida y `extra=forbid` en escrituras sensibles; `tests/test_mass_assignment.py` + tests de API/secretos; payload de evento abierto por contrato | PARTIAL |
| API4 Unrestricted Resource Consumption | rate limits, body/page limits, quotas, fair queue | DONE |
| API5 Broken Function Level Authorization | roles/capabilities por endpoint | DONE |
| API6 Unrestricted Access to Sensitive Business Flows | rotate-secret, reprocess DLQ y lifecycle protegidos; falta step-up/JIT | PARTIAL |
| API7 SSRF | URL validation, DNS checks, HTTPS, allowlists | PARTIAL (firewall/egress externo) |
| API8 Security Misconfiguration | production fail-closed, trusted hosts, headers, no docs en prod | PARTIAL (cloud/mesh/WAF externos) |
| API9 Improper Inventory Management | rutas OpenAPI y versión; no hay inventario/deprecation policy formal | PARTIAL |
| API10 Unsafe Consumption of APIs | Wazuh/OIDC timeouts, parsing defensivo, TLS, retries, circuit breaker y bulkhead | PARTIAL (breaker local; egress y coordinación distribuida externos) |

## Gaps críticos y prioridad

1. **Mass assignment/input strictness residual:** extender la matriz negativa a
   cualquier endpoint de escritura nuevo y revisar periódicamente payloads
   arbitrarios de ingesta sin convertirlos en configuración ejecutable.
2. **Referencias tenant entre recursos:** mantener pruebas PostgreSQL de las
   claves foráneas compuestas y añadirlas a cualquier nueva relación.
3. **Step-up/PAM/JIT:** proteger rotación de secretos, exportaciones y cambios
   privilegiados con reautenticación y acceso temporal.
4. **SSRF operativo:** demostrar deny-by-default, metadata blocking y egress
   allowlist fuera de la aplicación.
5. **WORM operativo:** configurar object lock, retención legal y una cuenta de
   exportación separada para el ledger.

La cobertura BOLA/IDOR de la superficie actual está demostrada por la suite
existente y `tests/test_bola_idor.py`; los gaps restantes son operativos o de
futuras rutas, no bypasses observados en los endpoints actuales.
