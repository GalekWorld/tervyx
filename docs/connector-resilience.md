# Resiliencia de conectores externos

La política común se aplica a Wazuh y OIDC mediante
`app/integrations/resilience.py`:

- timeout explícito en `httpx`;
- máximo de intentos acotado;
- backoff exponencial con jitter acotado y respeto de `Retry-After`;
- clasificación de errores: transporte, 408, 429 y 5xx son retryable; 4xx de
  autenticación/validación no se reintentan;
- circuit breaker por destino, compartido por las instancias del proceso;
- bulkhead por destino para limitar concurrencia;
- health/status persistido en `IntegrationAccount` y expuesto por
  `/api/v1/integrations/{id}/status`;
- fallos de procesamiento de eventos siguen el flujo existente de reintentos y
  DLQ/replay.

## Límites

El circuit breaker y el bulkhead son locales al proceso. La coordinación entre
réplicas requiere un estado compartido en la plataforma (Redis/service mesh),
además de límites de egress y alertas operativas. Esas medidas no se simulan ni
se consideran cubiertas por el código.
