# Pre-AI Security Gate

Fecha de revisión: 2026-09-02. Alcance: controles de seguridad y resiliencia
previos a cualquier fase con IA. Esta revisión no introduce IA ni cambios de
producto.

## Resultado por control

| Control | Estado | Evidencia | Tipo de gap |
|---|---|---|---|
| mTLS y segmentación de producción | **CONDICIONAL** | `docs/deployment.md` exige mTLS en mesh/ingress, PostgreSQL `verify-full` y egress solo del worker. Compose es explícitamente referencia de desarrollo. | Externo: mesh, CA, NetworkPolicy/firewall y certificados no existen en este repo. |
| Restore y PITR | **CONDICIONAL** | `scripts/backup_restore_drill.ps1/.sh`, backup custom-format diario, catálogo validado y restore drill en CI. PITR está documentado pero desactivado hasta disponer de WAL externo probado. | Externo: almacén WAL durable/cifrado, pruebas de RPO/RTO y ejecución operativa. |
| CI, pip-audit y advisories | **PASS** | `.github/workflows/ci.yml` bloquea locks obsoletos, `pip-audit --strict` con timeout, Bandit, Semgrep, Trivy, Gitleaks, SBOM, firma y ZAP. Verificación local reproducible: `pip-audit -r requirements.lock --strict --disable-pip`: `No known vulnerabilities found`. | El servicio de advisories debe permanecer accesible en cada ejecución CI. |
| Secretos y rotación | **PASS** | Backend de entorno rechazado en producción; Vault/OpenBao/AWS con rotación tenant-scoped; claves JWT con `kid` y ventana de rotación; secretos no se devuelven por API. | Ninguno de código identificado. |
| Mínimo privilegio | **PASS** | Rol runtime sin `BYPASSRLS`, propietario separado para migraciones/backups, contenedores non-root/read-only/cap-drop y capacidades explícitas. | La configuración de roles debe comprobarse en cada entorno. |
| Exposición de red | **PASS (repo)** | Backend Docker interno, gateway único publicado, PostgreSQL/Redis publicados solo en override de integración local; allowlists SSRF y egress worker documentados. | Externo: firewall/CNI debe impedir egress no permitido en producción. |
| RLS y aislamiento tenant | **PASS** | Políticas RLS, contexto tenant transaccional, FKs compuestas tenant-scoped y pruebas PostgreSQL reales de IDOR/cross-tenant/concurrencia. | Ninguno de código identificado. |
| Threat model y pruebas ofensivas | **PASS (repo)** | `docs/threat-model.md`; CI ejecuta Bandit, Semgrep, Gitleaks, Trivy y ZAP; suite ofensiva de auth/IDOR/SSRF/rate-limit. | E2E Wazuh y algunos servicios externos dependen de laboratorio autorizado. |

## Correcciones dependientes del repositorio

Se endureció previamente la construcción de `Settings` para fallar cerrado en
producción ante debug/rate-limit inseguro, backend de secretos por entorno,
claves ausentes, wildcards, URLs locales o Redis sin TLS. Este gate añade solo
esta documentación y no cambia comportamiento funcional.

## Bloqueantes para entrada en fase IA

1. Evidenciar mTLS real entre servicios y políticas de segmentación/egress en
   el entorno productivo.
2. Completar un restore/PITR real con WAL externo y registrar RPO/RTO medidos.
3. Mantener un `pip-audit` verde desde CI con advisories accesibles y conservar
   el resultado junto al artefacto/SBOM de release.

Con el bloque de dependencias/CI cerrado, permanecen como bloqueantes solo los
controles operativos de mTLS/segmentación y PITR descritos arriba. El resultado
global del gate continúa siendo **FAIL** hasta que plataforma los firme.
