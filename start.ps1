$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not (Test-Path -LiteralPath 'node_modules')) {
    npm ci
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
npm run build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'VunHunter: http://127.0.0.1:3001' -ForegroundColor Cyan
npm start
