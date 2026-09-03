# IaC y detección de drift

`infra/tofu` es un contrato declarativo OpenTofu/Terraform neutral de
proveedor. No crea recursos externos ni contiene credenciales: la selección de
cloud, cuenta, regiones, IDs de red y backend remoto se realiza fuera del repo.

Cada entorno usa un `*.tfvars` local/inyectado desde CI, nunca versionado. Los
ejemplos exigen gateway como único punto público; API, workers, PostgreSQL y
Redis privados; egress allowlisted; TLS, cifrado, backups/PITR; workload
identity; secretos externos rotables; y observabilidad privada con export de
auditoría. Los preconditions hacen fallar el plan si falta alguno.

## State, plan y apply

Inicializar sólo desde una identidad no humana con mínimo privilegio:

```bash
cd infra/tofu
tofu init -backend-config=/secure/path/staging.backend.hcl
tofu plan -var-file=/secure/path/staging.tfvars -out=/secure/path/staging.plan
tofu show -json /secure/path/staging.plan > /secure/path/staging.plan.json
```

El backend debe ser remoto, cifrado, versionado, bloqueado y dedicado a un
único entorno. Staging y producción requieren cuentas/proyectos, state keys,
identidades y secretos distintos. `apply` sólo se autoriza tras revisión de un
plan guardado y una aprobación protegida por el entorno CI; nunca desde una
workstation o PR.

## Drift y gates

El workflow programado `IaC Drift Detection` ejecuta periódicamente el mismo
`tofu plan -detailed-exitcode` con identidad
de sólo lectura. Exit code `2` es drift y debe abrir incidente; `0` significa
sin cambios; cualquier otro código falla el control. Comparar el JSON del plan
contra las políticas de organización del proveedor antes de aprobar un apply.

El workflow `IaC Guardrails` valida el contrato, prohíbe variables/backend
reales y secretos inline. `CODEOWNERS` designa revisión de plataforma para
infraestructura y workflows. La protección obligatoria de rama, aprobaciones,
OIDC de CI y ejecución programada de drift deben configurarse en GitHub y en
el proveedor: no pueden imponerse sólo con archivos del repositorio.
