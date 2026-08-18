<#
.SYNOPSIS
Offline adapter fixture gate. Default CI path; no provider credentials.

.DESCRIPTION
Runs the mesh-daemon adapters filter, which must stay offline. Credentialed
live adapter claims belong in test-live-adapters.ps1 and stay opt-in.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$startedAt = [DateTimeOffset]::UtcNow
$outcome = 'FAIL'
$reason = $null

try {
    $output = @(& cargo test -p mesh-daemon adapters 2>&1 | ForEach-Object { "$_" })
    if ($LASTEXITCODE -ne 0) { throw 'cargo test -p mesh-daemon adapters failed' }
    $ran = 0
    foreach ($line in $output) {
        if ($line -match 'running (\d+) tests?') { $ran += [int]$Matches[1] }
    }
    if ($ran -eq 0) { throw 'cargo test -p mesh-daemon adapters ran 0 tests' }
    $outcome = 'PASS'
} catch {
    $reason = $_.Exception.Message
    $outcome = 'FAIL'
}

$report = [ordered]@{
    fixture = 'adapter-fixtures-v1'
    outcome = $outcome
    reason = $reason
    started_at_utc = $startedAt.ToString('O')
    duration_ms = [int]([DateTimeOffset]::UtcNow - $startedAt).TotalMilliseconds
    live = $false
}
$report | ConvertTo-Json -Depth 6
if ($outcome -eq 'PASS') { exit 0 }
exit 1
