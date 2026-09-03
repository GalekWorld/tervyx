param(
  [Parameter(Mandatory=$true)][string]$Package,
  [Parameter(Mandatory=$true)][string]$Manifest,
  [Parameter(Mandatory=$true)][string]$ExpectedVersion
)
$ErrorActionPreference = 'Stop'
$m = Get-Content -Raw -Path $Manifest | ConvertFrom-Json
if ($m.product -ne 'tervyx-agent' -or $m.version -ne $ExpectedVersion) { throw 'Manifest identity/version mismatch' }
$actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Package).Hash.ToLowerInvariant()
if ($actual -ne $m.package_sha256.ToLowerInvariant()) { throw 'Package digest mismatch' }
if ($m.package_sha256 -match 'REPLACE_WITH' -or $m.signing_key_fingerprint -match 'REPLACE_WITH') { throw 'Unbound release metadata' }
# Signature verification is intentionally delegated to the enterprise signer
# (signtool/Authenticode or minisign) and must fail closed before msiexec.
Write-Output "PASS: digest verified for $($m.product) $($m.version)"
