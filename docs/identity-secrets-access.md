# Identity, Secrets & Access Control

## Modelo de confianza

La API mantiene los roles `admin`, `analyst` y `viewer`, pero cada operación protegida exige una
capability concreta. Los permisos base del rol se calculan en cada request y luego se aplican las
excepciones `allow`/`deny` de `user_capabilities`. Un cambio de rol, estado de usuario, capability
o sesión tiene efecto inmediato porque no se confía únicamente en los claims del JWT.

Los access tokens RS256 están ligados a una `AuthSession` mediante `sid`. Cada request comprueba
usuario, tenant, rol y sesión en PostgreSQL. Logout revoca la sesión y todos sus refresh tokens;
logout global revoca todas las sesiones del usuario. Los refresh tokens siguen siendo opacos,
hasheados y de un solo uso. En producción no se aceptan access tokens sin `sid`.

## OIDC empresarial

El flujo usa Authorization Code + PKCE S256, `state` de un solo uso, `nonce`, allowlist exacta de
redirect URI, discovery validado contra el issuer y verificación local de ID token mediante JWKS.
Solo se aceptan firmas RS256/ES256. La abstracción es OIDC estándar y el campo `provider_type`
admite Entra ID, Okta, Google, Keycloak y proveedores genéricos.

Para Entra ID:

1. Registrar una aplicación single-tenant y un redirect URI HTTPS exacto.
2. Crear el secreto en el secrets manager bajo `tenants/<organization_id>/oidc/entra`.
3. Configurar issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`, client ID, referencia
   al secreto y `provider_tenant_id` con el mismo tenant ID.
4. Aplicar Conditional Access para exigir MFA a administradores y configurar los claims del token.
   La API exige `oid`/`tid`, verifica `tid` y considera MFA solo valores permitidos de `amr`.
5. Preaprovisionar al usuario con el mismo email. No hay JIT provisioning: la primera autenticación
   enlaza la identidad federada con un usuario activo ya existente en ese tenant.

`OIDC_TRANSACTION_KEY` es una clave Fernet independiente de las claves JWT. Se genera con:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Debe rotarse mediante un rollout coordinado después de que expiren las transacciones OIDC de diez
minutos; nunca se registra ni persiste en PostgreSQL.

## Capabilities

- `security.read`, `events.ingest`
- `integrations.read`, `integrations.manage`, `integrations.execute`
- `dead_letters.read`, `dead_letters.reprocess`, `dead_letters.discard`
- `identity.manage`, `sessions.revoke`, `secrets.rotate`, `audit.read`

Los overrides se gestionan con `GET/PUT /api/v1/users/{id}/capabilities...` y quedan auditados.
RLS y filtros explícitos impiden consultar o modificar usuarios, sesiones, proveedores o secretos
de otro tenant aunque se manipulen UUID, `org` o `sid`.

## Secretos y rotación

`CredentialStore` ofrece `get(organization_id, reference)` y
`rotate(organization_id, reference, value)`. Vault KV v2, OpenBao KV v2 y AWS Secrets Manager
usan obligatoriamente el namespace `tenants/<organization_id>/...`; una referencia de otro tenant
se rechaza antes de llamar al proveedor. `EnvironmentCredentialStore` es solo desarrollo y no
permite rotación por API.

- Vault: `vault://tenants/<org>/...`, autenticación de workload y TLS.
- OpenBao: `openbao://tenants/<org>/...`, API KV v2 compatible, autenticación de workload y TLS.
- AWS: `aws-sm://tenants/<org>/...`, provider chain/IAM role limitado al prefijo del tenant. La
  rotación crea una nueva versión `AWSCURRENT`.

`POST /api/v1/integrations/{id}/rotate-secret` exige `secrets.rotate`. La API devuelve únicamente
la versión; ni el valor ni la referencia se incluyen en respuestas o AuditLog.

## Revocación de emergencia

1. Identificar y verificar dos veces el UUID exacto del tenant.
2. Revocar un usuario o todo el tenant. Añadir `--disable-oidc` si el proveedor está comprometido:

```bash
python -m app.scripts.emergency_revoke_access \
  --organization-id <uuid> --confirm-organization-id <uuid> \
  --reason "identity provider compromise" --disable-oidc
```

3. Rotar el secreto OIDC y las credenciales afectadas; reactivar el proveedor solo tras validar
   discovery y JWKS.
4. Rotar la clave JWT activa si existe sospecha de exfiltración, manteniendo la pública anterior
   solo durante el TTL imprescindible.
5. Revisar `auth.emergency_revocation`, logins OIDC, cambios de capability y rotaciones en AuditLog.

El comando fija el contexto RLS del tenant, revoca sesiones y refresh tokens de forma atómica y
genera auditoría sin incluir secretos.
