# Threat model — FASE 2.9

## Scope and trust boundaries

Tervyx receives security telemetry from tenant-owned integrations and persists it
in PostgreSQL. The principal trust boundaries are the public gateway, API
authentication boundary, tenant-scoped PostgreSQL session/RLS boundary, Redis
queue boundary, worker egress boundary, secrets providers and the CI/release
pipeline. Data is untrusted until schema validation and normalization complete.

Assets requiring protection are tenant telemetry, endpoint metadata, incident
state, credentials, signing keys, refresh tokens, audit records, release
artifacts and service availability. This phase does not grant workers an action
plane: workers may read integrations and write normalized telemetry only.

## Abuse cases and controls

| Scenario | Primary controls | Detection / recovery |
|---|---|---|
| Malicious tenant floods events or jobs | Per-tenant event, API, queue and job quotas; backpressure; fair scheduling | Quota/audit metrics; reject with 429/503 without dropping accepted events |
| Compromised admin changes access or secret references | MFA-protected admin sessions, capability checks, tenant-scoped secret paths, immutable audit records | Session/global revocation and emergency credential rotation procedure |
| Compromised worker attempts lateral movement | Non-root, read-only filesystem, dropped Linux capabilities, bounded resources, backend-only network; only worker has integration egress | Container/runtime alerts; rotate worker signing key and tenant credentials |
| Secret theft from API, worker or logs | Vault/OpenBao/AWS tenant namespace enforcement, secret redaction, no credentials in API responses, JWT log redaction | Revoke session/key, rotate affected tenant secret, audit access |
| SSRF through an integration URL | HTTPS-only URL validation, no embedded credentials, DNS/IP classification, allowlist/private-network policy, isolated worker egress | Reject malformed/unsafe URLs; investigate DNS and audit integration changes |
| DNS rebinding / redirect to internal service | Resolve and validate targets before use; production allowlist; worker is the only egress service | Egress firewall must enforce allowlist independently of DNS; see deployment policy |
| JWT/refresh-token replay | RS256 with `kid`/JWKS, short-lived access tokens, session binding, rotation and server-side revocation | Revoke refresh token/session; rotate signing key for broad compromise |
| Capability or role escalation | Role is revalidated from tenant-scoped database on every request; explicit capability grants; RLS | Audit identity changes; adversarial IDOR/capability tests in CI |
| Cross-tenant IDOR or direct SQL access | Token-derived organization, RLS, repository predicates, tenant context in workers, tenant secret namespaces | API/RLS/concurrency tests; return 404 for inaccessible resources |
| Supply-chain compromise | Hash-locked dependencies, immutable base digest, SBOM, signed release image, SAST/DAST/dependency gates | Reject unsigned/unscanned artifacts; incident procedure below |

## Residual risks

Docker Compose is a development/reference topology, not a network policy engine.
Production must enforce egress allowlists at the Kubernetes CNI/firewall and
validate mTLS identities at the service mesh or ingress layer. A compromised
database owner bypasses RLS; that role is restricted to migrations/backups and
is never used by API/workers. Social-engineering and compromised IdP accounts
remain dependent on Entra conditional-access policy.

## Security incident actions

1. Disable the impacted integration and revoke affected sessions.
2. Rotate the tenant-scoped secret in Vault/OpenBao/AWS Secrets Manager.
3. If a signing key is suspected, publish a new JWKS `kid`, switch active key,
   revoke sessions and retire the old key after token TTL.
4. Preserve audit logs, DLQ payload metadata and release digest for forensics.
5. Rebuild from the signed release digest only; never rebuild an incident image
   from an unreviewed branch.
