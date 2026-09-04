# Tervyx mTLS probe

Servicio independiente para validar mTLS en staging. No forma parte de la API
productiva y no contiene certificados ni claves.

## Variables

Requeridas, apuntando a secretos montados como archivos legibles por el usuario
`probe`:

- `MTLS_PROBE_CA_FILE`: CA que firma los certificados cliente aceptados.
- `MTLS_PROBE_SERVER_CERT_FILE`: certificado TLS del probe.
- `MTLS_PROBE_SERVER_KEY_FILE`: clave privada del certificado del probe.

Opcional:

- `MTLS_PROBE_PORT` (por defecto `8443`).

## Northflank

Crear un servicio separado con contexto `mtls-probe/`, Dockerfile
`mtls-probe/Dockerfile`, puerto `8443` y los tres secretos montados como
archivos. El comando de arranque por defecto es:

```text
python probe.py
```

La forma de montar secretos depende de la configuración de secretos/volúmenes
del proyecto Northflank; no se guardan PEM en Git ni en la imagen.

## Validación

Con CA, certificado y clave de cliente válidos:

```bash
curl --fail --cacert staging-ca.pem \
  --cert worker-client.pem --key worker-client.key \
  https://probe.staging.example:8443/internal/mtls-probe
```

Debe devolver HTTP 200 y `"mtls": "client_certificate_verified"`.

Sin certificado cliente, el handshake TLS debe fallar:

```bash
curl --fail --cacert staging-ca.pem \
  https://probe.staging.example:8443/internal/mtls-probe
```

El endpoint no debe ser accesible sin un certificado cliente emitido por la CA
configurada.
