param(
  [Parameter(Mandatory=$true)][string]$Package,
  [Parameter(Mandatory=$true)][string]$Manifest,
  [Parameter(Mandatory=$true)][string]$SlotRoot,
  [Parameter(Mandatory=$true)][string]$SignerThumbprint
)
$ErrorActionPreference = 'Stop'
$m = Get-Content -Raw -Path $Manifest | ConvertFrom-Json
if ($m.product -ne 'tervyx-agent' -or $m.version -match 'REPLACE_WITH') { throw 'Invalid update manifest' }
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Package).Hash.ToLowerInvariant()
if ($hash -ne $m.package_sha256.ToLowerInvariant()) { throw 'Digest mismatch' }
$signature = Get-AuthenticodeSignature -FilePath $Package
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint.Replace(' ', '').ToUpperInvariant() -ne $SignerThumbprint.Replace(' ', '').ToUpperInvariant()) { throw 'Authenticode signature is not trusted' }
$statePath = Join-Path $SlotRoot 'active-slot.json'
$state = if (Test-Path $statePath) { Get-Content -Raw $statePath | ConvertFrom-Json } else { [pscustomobject]@{slot='A'; version='0.0.0'; previous=$null} }
if ([version]$m.version -le [version]$state.version) { throw 'Downgrade or duplicate version rejected' }
$inactive = if ($state.slot -eq 'A') { 'B' } else { 'A' }
$slot = Join-Path $SlotRoot $inactive
New-Item -ItemType Directory -Force -Path $slot | Out-Null
Copy-Item -LiteralPath $Package -Destination (Join-Path $slot 'Tervyx.Agent.msi') -Force
$next = [ordered]@{ slot=$inactive; version=$m.version; previous=$state.slot; previous_version=$state.version; digest=$hash }
$tmp = "$statePath.$([guid]::NewGuid()).tmp"
$next | ConvertTo-Json | Set-Content -Encoding UTF8 $tmp
Move-Item -Force $tmp $statePath
Write-Output "PASS: staged signed version $($m.version) in slot $inactive; restart service and health-check before retiring $($state.slot)"
