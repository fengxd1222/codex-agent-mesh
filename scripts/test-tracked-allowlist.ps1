[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$verificationScript = Join-Path $PSScriptRoot "verify-tracked-allowlist.ps1"

& $verificationScript -IndexPaths @(
    "README.md",
    "eslint.config.mjs",
    "protocol/v1/schema.json",
    "tests/acceptance-matrix.json"
)

$rejected = $false
try {
    & $verificationScript -IndexPaths @(".claude/forbidden.txt")
}
catch {
    $rejected = $_.Exception.Message -match "Git index contains paths outside"
}

if (-not $rejected) {
    throw "Tracked allowlist verification must reject a disallowed staged path."
}

Write-Output "Tracked allowlist index classification regression test passed."
