<#
.SYNOPSIS
Fail-closed entry point for the M4 crash/retry matrix.

.DESCRIPTION
Requires every case in tests/process-fixtures/crash-matrix/required-cases.txt
to appear in `cargo test -p mesh-daemon -- --list`, then runs the crash_matrix
and retry cargo filters. A missing case is a failure, not a skip.
#>
[CmdletBinding()]
param(
    [switch]$ListOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$catalogPath = Join-Path $repositoryRoot 'tests\process-fixtures\crash-matrix\required-cases.txt'
$startedAt = [DateTimeOffset]::UtcNow
$outcome = 'FAIL'
$reason = $null
$evidence = [ordered]@{}

function Get-RequiredCrashMatrixCases {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "crash-matrix catalog is missing: $Path"
    }
    $names = @(
        Get-Content -LiteralPath $Path |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith('#') }
    )
    if ($names.Count -eq 0) { throw 'crash-matrix catalog is empty' }
    return $names
}

function Get-ListedMeshDaemonTests {
    $listOutput = & cargo test -p mesh-daemon -- --list
    if ($LASTEXITCODE -ne 0) { throw 'cargo test --list failed for mesh-daemon' }
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($line in @($listOutput)) {
        if ($line -match '^\s*(?<name>\S+):\s+test\s*$') {
            $names.Add($Matches['name'])
        }
    }
    if ($names.Count -eq 0) { throw 'cargo test --list returned no mesh-daemon tests' }
    return $names
}

function Invoke-CargoTestFilter {
    param([Parameter(Mandatory)][string]$Filter)
    $output = @(& cargo test -p mesh-daemon $Filter 2>&1 | ForEach-Object { "$_" })
    if ($LASTEXITCODE -ne 0) { throw "cargo test -p mesh-daemon $Filter failed" }
    $ran = 0
    foreach ($line in $output) {
        if ($line -match 'running (\d+) tests?') { $ran += [int]$Matches[1] }
    }
    if ($ran -eq 0) { throw "cargo test -p mesh-daemon $Filter ran 0 tests" }
}

function Test-CasePresent {
    param(
        [Parameter(Mandatory)][string]$Required,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Listed
    )
    foreach ($entry in $Listed) {
        $leaf = ($entry -split '::')[-1]
        if ($entry -eq $Required -or $leaf -eq $Required) { return $true }
    }
    return $false
}

try {
    $required = @(Get-RequiredCrashMatrixCases -Path $catalogPath)
    $evidence.required_cases = $required
    $listed = @(Get-ListedMeshDaemonTests)
    $evidence.listed_count = $listed.Count
    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($case in $required) {
        if (-not (Test-CasePresent -Required $case -Listed $listed)) {
            $missing.Add($case)
        }
    }
    $evidence.missing_cases = @($missing)
    if ($missing.Count -gt 0) {
        throw ("crash-matrix cases missing from cargo test --list: " + ($missing -join ', '))
    }

    $retryNamed = @($required | Where-Object { $_ -match 'retry' })
    if ($retryNamed.Count -eq 0) {
        throw 'crash-matrix catalog has no retry-named cases; cargo test retry would prove nothing'
    }
    $evidence.retry_named_cases = $retryNamed

    if ($ListOnly) {
        $outcome = 'PASS'
        $evidence.list_only = $true
    } else {
        Invoke-CargoTestFilter -Filter 'crash_matrix'
        $evidence.crash_matrix_filter = 'PASS'
        Invoke-CargoTestFilter -Filter 'retry'
        $evidence.retry_filter = 'PASS'
        $outcome = 'PASS'
    }
} catch {
    $reason = $_.Exception.Message
    $outcome = 'FAIL'
}

$report = [ordered]@{
    fixture = 'crash-matrix-v1'
    outcome = $outcome
    reason = $reason
    started_at_utc = $startedAt.ToString('O')
    duration_ms = [int]([DateTimeOffset]::UtcNow - $startedAt).TotalMilliseconds
    evidence = $evidence
}
$report | ConvertTo-Json -Depth 8
if ($outcome -eq 'PASS') { exit 0 }
exit 1
