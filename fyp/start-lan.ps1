$ErrorActionPreference = 'Stop'

$env:HBW_PUBLIC_LINK_ORIGIN = 'https://honeybound.192-168-1-2x.nip.io:8443'
$env:HBW_TLS_PFX_PATH = 'server/lan-domain-cert.pfx'

if (-not $env:HBW_TLS_PFX_PASSPHRASE) {
  throw 'Set HBW_TLS_PFX_PASSPHRASE in your shell before running start-lan.ps1.'
}

if (-not $env:HBW_DATA_KEY) {
  throw 'Set HBW_DATA_KEY in your shell before running start-lan.ps1.'
}

Write-Host "Starting HoneyBound with LAN HTTPS at $env:HBW_PUBLIC_LINK_ORIGIN" -ForegroundColor Cyan
node server/server.js
