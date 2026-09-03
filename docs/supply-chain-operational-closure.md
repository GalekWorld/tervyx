# Supply-chain operacional

El repositorio prepara controles y evidencia, pero no afirma configuración de
GitHub, GHCR ni admission como hecho externo.

## GitHub

```bash
python scripts/validate_supply_chain.py
GITHUB_REPOSITORY=ORG/REPO GITHUB_TOKEN="$READ_ONLY_TOKEN" \
  python scripts/check_github_protection.py --check --branch main
```

El resultado PASS debe conservarse como artefacto del control. Además, la
protección debe requerir PR, CODEOWNER `@tervyx-platform`, todos los checks,
una aprobación independiente, conversación resuelta, no force-push/delete y
administrators incluidos. Los commits y tags `v*` deben ser firmados y la
creación de tags restringida a release maintainers.

## Registry y admission

GHCR debe aplicar repositorio privado, tags inmutables, digest obligatorio,
retención definida y rechazo de imágenes sin firma/attestation. Sustituir los
placeholders de [tervyx-admission.yaml](../infra/policies/tervyx-admission.yaml)
en un repositorio de plataforma, validar con `kyverno apply`/OPA y activar
`Enforce` sólo tras probar un digest firmado y uno unsigned.

## Releases

`release.yml` genera imagen por digest, SBOM SPDX, attestation GitHub y firma
Cosign keyless. La evidencia mínima a conservar es digest, SBOM, attestation,
salida de [verify_release_artifacts.sh](../scripts/verify_release_artifacts.sh),
commit/tag y aprobaciones del entorno. El despliegue
debe usar una identidad CI de build separada de la identidad de deploy; deploy
sólo acepta digests verificados y no puede publicar artefactos.

Para una release concreta, ejecutar con Cosign configurado en el runner:

```bash
git verify-tag "$TAG"                         # tag anotado y firmado
IMAGE=ghcr.io/ORG/tervyx DIGEST=sha256:... \
  REPOSITORY=ORG/REPO scripts/verify_release_artifacts.sh
```

## Gaps externos

Branch protection, required reviewers, firma de commits/tags, reglas GHCR,
OIDC trust policy, permisos de environments, admission controller, política de
retención y almacenamiento de evidencias no son configurables de forma segura
desde este repo. Deben aportar evidencias fechadas desde GitHub, registry y
staging antes de declarar el control operativo PASS.
