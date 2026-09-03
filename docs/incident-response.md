# Incident Response

Este documento es el procedimiento operativo determinista de Tervyx. Todo
incidente conserva timestamps UTC, tenant, actor, sistema afectado, decisiones,
artefactos y hashes del audit ledger. Nunca se reutilizan credenciales ni se
modifican evidencias originales.

## Severidad y escalado

| Nivel | Criterio mínimo | Respuesta | Escalado máximo |
|---|---|---|---|
| SEV-1 | fuga de datos, tenant escape confirmado, credencial de producción o supply-chain comprometida, indisponibilidad total | activar Incident Commander en 15 min, contener inmediatamente, preservar evidencia | 30 min a seguridad, dirección y legal |
| SEV-2 | compromiso probable, impacto multi-servicio o degradación grave | owner en 30 min, contención en 1 h | 2 h a seguridad |
| SEV-3 | impacto tenant limitado o control degradado | owner en 4 h, remediación en 1 día hábil | jornada laboral |
| SEV-4 | hallazgo sin impacto activo | backlog y revisión semanal | owner del servicio |

## Roles

- **Incident Commander:** autoridad única de prioridad y cierre.
- **Security Lead:** triage, contención, threat model y preservación forense.
- **Service Owner:** cambios técnicos, rollback y validación de recuperación.
- **Data/Privacy + Legal:** alcance de datos y notificaciones regulatorias.
- **Communications:** mensajes aprobados a clientes/proveedores.
- **Scribe:** timeline, evidencias, decisiones y enlaces inmutables.

## Playbooks

**Credential compromise:** revocar sesión/JIT y secretos, bloquear tokens,
rotar desde el custodio externo, revisar ledger y accesos desde el primer uso.

**Tenant escape:** aislar actor y workload, preservar RLS/DB logs, congelar
exports, identificar tenants afectados y ejecutar pruebas cross-tenant.

**Data breach:** detener exfiltración, conservar snapshot/hash, determinar
datos y jurisdicciones, coordinar Legal y notificar sólo tras aprobación.

**Insider threat:** preservar evidencia sin alertar al sospechoso, revocar JIT,
aplicar separación de funciones y solicitar revisión independiente.

**Supply-chain compromise:** detener releases, fijar digest conocido, revocar
credenciales CI, comparar SBOM/provenance y reconstruir desde commit verificado.

**Outage:** declarar severidad por impacto, congelar cambios, priorizar
recuperación/rollback, validar integridad y comunicar RTO/RPO medidos.

Cada playbook exige: declarar incidente, asignar roles, crear timeline,
contener, erradicar, recuperar, notificar según impacto, revisión posterior y
acciones con owner/fecha.
