# Seguridad y tenancy

## Identidad y autorización

Los JWT RS256 requieren `kid`, `iss`, `aud`, `iat`, `exp`, `jti`, `sub`, `org` y `type`. El
backend valida algoritmo, clave rotada y claims, carga al usuario activo bajo el tenant del token y compara el rol almacenado;
un cambio de rol invalida de facto tokens antiguos. La jerarquía es `viewer < analyst < admin`.
Los jobs Celery reciben tokens de audiencia separada, ligados a una integración concreta. JWKS
se publica en `/.well-known/jwks.json`; `JWT_VERIFICATION_KEYS_JSON` conserva claves públicas
anteriores durante una rotación. Los refresh tokens son opacos, se almacenan hasheados, rotan en
cada uso y están ligados a sesiones revocables. OIDC usa Authorization Code + PKCE, nonce,
transacciones de un solo uso y JWKS. En producción los administradores solo pueden entrar por SSO
con MFA verificada. Los roles se mantienen, pero cada operación exige una capability. El diseño
completo está en `docs/identity-secrets-access.md`.

## Aislamiento multi-tenant

Los repositorios filtran por organización y PostgreSQL aplica `ENABLE/FORCE ROW LEVEL SECURITY`
a todas las tablas sensibles y asociaciones. La variable transaccional
`app.current_organization_id` se fija después de autenticar y se restaura en cada entrada de
servicio/worker tras commits o rollbacks. El rol runtime `soc_app` no es propietario, superusuario
ni dispone de `BYPASSRLS`.

## Controles de borde

- URLs de integración: solo HTTPS, sin userinfo, resolución DNS completa y rechazo de cualquier
  IP privada, loopback, link-local, reservada o no global.
- Host header restringido con Trusted Hosts y CORS sin wildcard ni credenciales.
- Rate limit Redis fail-closed; salud y métricas quedan fuera del contador.
- Payload máximo 1 MiB por defecto; paginación de 1 a 200; filtros con tipos y rangos.
- Respuestas 500 no incluyen excepciones; logs, DLQ y estado de integración usan sanitización.
- Swagger/ReDoc/OpenAPI se deshabilitan automáticamente con `APP_ENV=production`.
- Creación/sync/test de integraciones, login correcto y operaciones DLQ generan AuditLog.

## Secretos

`CredentialStore` expone `get` y `rotate`, siempre con `organization_id`. El backend de entorno
lee JSON por referencia solo para desarrollo; Vault KV v2, OpenBao KV v2 y AWS Secrets Manager
usan namespaces obligatorios por tenant. No se devuelve
`credential_reference` en schemas públicos y nunca se almacena el secreto en PostgreSQL.
En producción `EnvironmentCredentialStore` se rechaza. Vault KV v2 fue validado contra un
servidor real de laboratorio; para producción se exige Vault TLS y autenticación de workload (o
AWS Secrets Manager mediante su provider chain), nunca el modo dev ni tokens raíz estáticos.
