# Tabletop reproducible

Ejecutar en staging, con datos sintéticos y un tenant de laboratorio:

```bash
export TABLETOP_ID="$(date -u +%Y%m%dT%H%M%SZ)-tenant-escape"
mkdir -p "evidence/$TABLETOP_ID"
date -u +%FT%TZ | tee "evidence/$TABLETOP_ID/start.txt"
```

1. El facilitador inyecta un intento cross-tenant y una credencial expuesta.
2. El operador declara SEV-1, asigna Incident Commander/Scribe y captura
   eventos, señales, ledger exportado y estado de sesiones.
3. Se revoca la sesión JIT, se rota el secreto de prueba y se verifica que el
   tenant ajeno no sea visible.
4. Se simula una imagen no aprobada; CI debe bloquearla por digest/SBOM.
5. Se ejecuta el restore drill y se registran tiempos RPO/RTO.
6. Se cierra sólo con timeline, decisiones, evidencias con SHA-256,
   notificaciones simuladas y acciones correctivas con owner y fecha.

El ejercicio es reproducible únicamente en staging autorizado; no usar datos
reales ni provocar indisponibilidad de producción.
