param(
    [ValidateSet(10000, 100000, 500000, 1000000)]
    [int]$Count = 10000,
    [int]$Workers = 2,
    [int]$BatchSize = 500,
    [int]$Tenants = 20,
    [int]$TimeoutSeconds = 3600
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $workspace.EndsWith("SOC")) {
    throw "Refusing to run outside the SOC workspace"
}

Push-Location $workspace
try {
    # Use the same integration compose topology as the real PostgreSQL/Redis suite;
    # mixing it with the base project can detach live workers from its network.
    $compose = @("-f", "docker-compose.yml", "-f", "docker-compose.integration.yml")
    docker compose @compose up -d --scale worker=$Workers db redis jwt-keys migrate worker
    $workerIds = @(docker compose @compose ps -q worker)
    if ($workerIds.Count -ne $Workers) {
        throw "Expected $Workers Celery workers, found $($workerIds.Count)"
    }
    $statsJob = Start-Job -ArgumentList (, $workerIds) -ScriptBlock {
        param($ids)
        while ($true) {
            docker stats --no-stream --format '{{json .}}' $ids
            Start-Sleep -Seconds 1
        }
    }
    try {
        docker compose @compose run --rm --no-deps api python -m app.scripts.benchmark_celery `
            --count $Count --batch-size $BatchSize --timeout $TimeoutSeconds `
            --tenants $Tenants
    }
    finally {
        Stop-Job $statsJob -ErrorAction SilentlyContinue
        $stats = @(Receive-Job $statsJob -ErrorAction SilentlyContinue)
        Remove-Job $statsJob -Force -ErrorAction SilentlyContinue
        $stats | Where-Object { $_ } | ForEach-Object { $_ } | ConvertTo-Json -Compress
    }
}
finally {
    Pop-Location
}
