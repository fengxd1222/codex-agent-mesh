<#
.SYNOPSIS
Opt-in live adapter contract gate. Never run by default CI.

.DESCRIPTION
Requires MESH_LIVE_ADAPTER_TESTS=1. Runs the ignored live_contract tests in
mesh-daemon, which drive the locally installed Claude, Grok, and Kimi CLIs
through the supervisor with real (credentialed) sessions, then read the
machine-local evidence records each test writes. A missing executable keeps
that adapter at NOT RUN (executable-not-found) rather than failing the whole
gate; a failing contract records FAIL evidence and fails the script.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$enabled = $env:MESH_LIVE_ADAPTER_TESTS -eq '1'
$startedAt = [DateTimeOffset]::UtcNow
$fixture = 'live-adapters-v2'

function Read-EvidenceRecord {
    param([string]$Adapter)
    $dir = if ($env:MESH_LIVE_EVIDENCE_DIR) {
        $env:MESH_LIVE_EVIDENCE_DIR
    } else {
        Join-Path $PSScriptRoot '..\target\live-adapter-evidence'
    }
    $file = Join-Path $dir "$($Adapter.ToLowerInvariant()).json"
    if (-not (Test-Path $file)) { return $null }
    try {
        return Get-Content -Raw $file | ConvertFrom-Json
    } catch {
        return $null
    }
}

function Adapter-Status {
    param([string]$Adapter)
    $record = Read-EvidenceRecord -Adapter $Adapter
    if ($null -eq $record) { return 'NOT RUN' }
    if ($record.outcome -eq 'PASS') { return 'PASS' }
    return 'FAIL'
}

if (-not $enabled) {
    $report = [ordered]@{
        fixture = $fixture
        outcome = 'NOT RUN'
        reason = 'MESH_LIVE_ADAPTER_TESTS is not 1; live adapter tests stay opt-in'
        started_at_utc = $startedAt.ToString('O')
        duration_ms = [int]([DateTimeOffset]::UtcNow - $startedAt).TotalMilliseconds
        live = $true
        opt_in = $false
        claude = 'NOT RUN'
        grok = 'NOT RUN'
        kimi = 'NOT RUN'
    }
    $report | ConvertTo-Json -Depth 6
    exit 0
}

$evidenceDir = if ($env:MESH_LIVE_EVIDENCE_DIR) {
    $env:MESH_LIVE_EVIDENCE_DIR
} else {
    Join-Path $PSScriptRoot '..\target\live-adapter-evidence'
}
if (Test-Path $evidenceDir) {
    # Stale evidence from a previous run must not leak into this report.
    Remove-Item -Recurse -Force $evidenceDir
}

$reason = $null
try {
    & cargo test -p mesh-daemon --lib -- --ignored live_contract 2>&1 | ForEach-Object { "$_" }
    if ($LASTEXITCODE -ne 0) { $reason = 'cargo live_contract tests failed' }
} catch {
    $reason = $_.Exception.Message
}

$claude = Adapter-Status -Adapter 'claude'
$grok = Adapter-Status -Adapter 'grok'
$kimi = Adapter-Status -Adapter 'kimi'
$anyPass = ($claude -eq 'PASS') -or ($grok -eq 'PASS') -or ($kimi -eq 'PASS')
$anyFail = ($claude -eq 'FAIL') -or ($grok -eq 'FAIL') -or ($kimi -eq 'FAIL')
$outcome = if ($reason -or $anyFail) {
    'FAIL'
} elseif ($anyPass) {
    # A provider that ran and passed proves the harness end to end;
    # per-adapter fields above carry the honest detail.
    'PASS'
} else {
    'NOT RUN'
}

$report = [ordered]@{
    fixture = $fixture
    outcome = $outcome
    reason = $reason
    started_at_utc = $startedAt.ToString('O')
    duration_ms = [int]([DateTimeOffset]::UtcNow - $startedAt).TotalMilliseconds
    live = $true
    opt_in = $true
    evidence_dir = $evidenceDir
    claude = $claude
    grok = $grok
    kimi = $kimi
}
$report | ConvertTo-Json -Depth 6
if ($outcome -eq 'FAIL') { exit 1 }
exit 0
