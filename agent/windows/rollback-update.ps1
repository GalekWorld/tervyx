param([Parameter(Mandatory=$true)][string]$SlotRoot)
$ErrorActionPreference = 'Stop'
$statePath = Join-Path $SlotRoot 'active-slot.json'
$state = Get-Content -Raw $statePath | ConvertFrom-Json
if (-not $state.previous -or -not $state.previous_version) { throw 'No rollback slot available' }
$previousVersion = (Get-ChildItem (Join-Path $SlotRoot $state.previous) -Filter '*.msi' | Select-Object -First 1).Name
if (-not $previousVersion) { throw 'Previous slot is incomplete' }
$next = [ordered]@{ slot=$state.previous; version=$state.previous_version; previous=$state.slot; previous_version=$state.version }
$tmp = "$statePath.$([guid]::NewGuid()).tmp"
$next | ConvertTo-Json | Set-Content -Encoding UTF8 $tmp
Move-Item -Force $tmp $statePath
Write-Output "PASS: active slot switched to $($state.previous); reinstall and health-check the preserved package"
