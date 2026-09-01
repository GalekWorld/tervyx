# Benchmark productivo de ingestión

Comando: `scripts/run_productive_benchmark.ps1 -Count 10000 -Workers 2`. Usa PostgreSQL 16,
Redis 7, Celery, dos contenedores worker y el pipeline completo adapter/persistencia/auditoría.
La latencia es extremo a extremo desde enqueue e incluye espera en cola.

| Eventos | Persistidos | Errores | events/s | p50 | p95 | p99 | Cola máx. | Locks bloqueados |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10.000 | 10.000 | 0 | 248,59 | 22,37 s | 38,53 s | 39,80 s | 1.050 | 0 |
| 100.000 | 100.000 | 0 | 249,63 | 189,93 s | 372,87 s | 392,51 s | 7.724 | 0 |

Pico observado por worker: ~407 %/~396 % CPU y ~735/~732 MiB en 10k; durante 100k se
mantuvieron alrededor de 350 % CPU y 774/771 MiB. PostgreSQL alcanzó ~124 % CPU y ~261 MiB;
Redis ~59 % CPU y ~96 MiB. Un millón proyecta ~66,8 minutos a esta tasa, por lo que no fue viable
en este host de desarrollo; el runner admite `-Count 1000000` para staging dimensionado.

El throughput estable y la cola creciente muestran que la deuda principal es el commit por
evento. No se introdujo batching porque sería una modificación funcional fuera de Fase 2.6.
