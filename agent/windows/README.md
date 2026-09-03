# Tervyx Windows Endpoint Agent

Base persistente para Windows Service (`net8.0-windows`). El agente usa una
identidad por endpoint y un token de enrolamiento protegido con DPAPI
`LocalMachine`; nunca se guarda en el repositorio ni en argumentos de proceso.
El heartbeat está limitado por timeout y no ejecuta acciones remotas.

Publicar con `dotnet publish -c Release -r win-x64 --self-contained true`,
provisionar el token mediante `SecretStore.ProvisionToken` en contexto elevado y
empaquetar con `Installer/Product.wxs`. Firmar MSI y catálogo antes de distribuir.
Intune/GPO ejecutará `/qn /norestart`; el instalador debe comprobar el arranque
del servicio y hacer rollback si falla.

La renovación mTLS con certificado en `LocalMachine\\My` y el canal de auto-update
A/B se validan contra `update-manifest.example.json` y `verify-update.ps1` antes
de reemplazar el binario; conservar la versión anterior para rollback. Action
Plane y ejecución remota están fuera de alcance.
