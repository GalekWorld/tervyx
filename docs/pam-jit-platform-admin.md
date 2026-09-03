# PAM/JIT para Platform Admin

Tervyx mantiene la elegibilidad (`platform_admin_eligibilities`) separada de
la elevación efectiva. Ser elegible no añade capabilities al token normal ni
crea un rol global. Cada solicitud crea una concesión temporal por tenant,
con propósito, capacidades mínimas, vencimiento y aprobación separada.

La activación exige una sesión base vigente y MFA reciente. El IdP aporta los
`amr`; FIDO2, passkey/WebAuthn, hardware y `ngcmfa` son métodos aceptados por
la política por defecto. La sesión JIT se materializa aparte, no tiene refresh
token y queda ligada a la sesión base: revocar ésta invalida inmediatamente el
token privilegiado aunque aún no haya expirado.

## Flujo

1. Un usuario elegible con MFA reciente solicita sólo las capabilities
   `platform.*` necesarias.
2. Un segundo elegible aprueba; el solicitante no puede autoaprobarse.
3. La activación crea una sesión JIT de corta duración y un JWT vinculado a
   ambos IDs de sesión. Se serializa con locks por fila y advisory lock en
   PostgreSQL.
4. Revocación, expiración, rechazo de MFA obsoleto y acceso cross-tenant son
   fail-closed.

Break-glass sólo funciona si la política tenant lo habilita, requiere MFA,
una razón que empieza por `break-glass:` y deja eventos `pam.*` en `AuditLog`.
El ledger los sella automáticamente.

## Límites operativos

El desafío FIDO2/passkey/hardware y la señal `amr` se ejecutan en el IdP;
Tervyx valida la evidencia recibida y su frescura, pero no sustituye al
registrador de credenciales ni al hardware. La provisión inicial de
elegibilidades y el custodio de break-glass deben operar desde el IdP o un
canal administrativo de infraestructura separado.
