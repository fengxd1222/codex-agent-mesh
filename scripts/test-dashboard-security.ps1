<#
.SYNOPSIS
Offline dashboard security acceptance. Never uses the retained install.

.DESCRIPTION
Runs the deterministic dashboard HTTP tests, then the ignored Edge CDP
fixture against a marker-owned temporary data root with a sibling junction
at data\assets. Missing Edge or junction privilege is NOT RUN, never PASS.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\tests\process-fixtures\singleton-reconnect\ProcessAcceptance.Common.ps1')

$startedAt = [DateTimeOffset]::UtcNow
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$testName = 'dashboard::dashboard_tests::edge_security_acceptance'
$workspace = $null
$outside = $null
$junction = $null
$sentinel = "mesh-m6-sentinel-$([guid]::NewGuid().ToString('N'))"
$cases = [ordered]@{
    unit = 'NOT RUN'
    catalogue = 'NOT RUN'
    junction = 'NOT RUN'
    browser = 'NOT RUN'
}

function Find-Edge {
    foreach ($candidate in @(
            "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
            "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
        )) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return $candidate
        }
    }
    return $null
}

function Write-Report {
    param([string] $Outcome, [string] $Reason)
    $report = [ordered]@{
        fixture = 'dashboard-security-v1'
        outcome = $Outcome
        reason = $Reason
        started_at_utc = $startedAt.ToString('O')
        duration_ms = [int]([DateTimeOffset]::UtcNow - $startedAt).TotalMilliseconds
        live = $false
        cases = $cases
    }
    $report | ConvertTo-Json -Depth 6
}

$reason = $null
$outcome = 'FAIL'
try {
    Push-Location -LiteralPath $repo
    $list = @(& cargo test -p mesh-daemon --lib -- --list 2>&1 | ForEach-Object { "$_" })
    if ($LASTEXITCODE -ne 0) { throw 'could not list mesh-daemon library tests' }
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($line in $list) {
        if ($line -match '^(.+): test$') { [void]$names.Add($Matches[1]) }
    }
    if (-not $names.Contains($testName)) {
        throw "exact test absent from catalogue: $testName"
    }
    $cases.catalogue = 'PASS'

    & cargo test -p mesh-daemon dashboard --lib -- --test-threads=1
    if ($LASTEXITCODE -ne 0) { throw 'dashboard unit tests failed' }
    $cases.unit = 'PASS'

    $workspace = New-ProcessFixtureWorkspace 'mesh-dashboard-security-'
    $outside = Join-Path $workspace 'outside'
    $data = Join-Path $workspace 'data'
    [void](New-Item -ItemType Directory -Path $outside)
    [void](New-Item -ItemType Directory -Path $data)
    [IO.File]::WriteAllText((Join-Path $outside 'must-survive.txt'), $sentinel)
    [IO.File]::WriteAllText((Join-Path $outside 'dashboard.js'), 'outside-decoy-dashboard-js')
    $junction = Join-Path $data 'assets'
    [void](New-Item -ItemType Junction -Path $junction -Target $outside)
    $junctionItem = Get-Item -Force -LiteralPath $junction
    if (($junctionItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
        throw 'assets junction is not a reparse point'
    }

    $edge = Find-Edge
    if (-not $edge) {
        $cases.browser = 'NOT RUN'
        throw 'Edge executable was not found'
    }

    $env:MESH_DASHBOARD_SECURITY_ROOT = $data
    $env:MESH_DASHBOARD_SECURITY_DRIVER = Join-Path $repo 'tests\dashboard-fixtures\edge-cdp.mjs'
    $env:MESH_DASHBOARD_SECURITY_EDGE = $edge
    $env:MESH_DASHBOARD_SECURITY_PROFILE = Join-Path $workspace 'edge-profile'
    [void](New-Item -ItemType Directory -Path $env:MESH_DASHBOARD_SECURITY_PROFILE)

    & cargo test -p mesh-daemon --lib $testName -- --exact --ignored --test-threads=1
    if ($LASTEXITCODE -ne 0) {
        $cases.browser = 'FAIL'
        throw 'edge security acceptance failed'
    }
    $cases.browser = 'PASS'

    $decoy = [IO.File]::ReadAllText((Join-Path $outside 'must-survive.txt'))
    if ($decoy -cne $sentinel) { throw 'outside sentinel changed' }
    $cases.junction = 'PASS'
    $outcome = 'PASS'
} catch {
    $reason = $_.Exception.Message
    if ($cases.browser -eq 'NOT RUN') {
        $outcome = 'NOT RUN'
    } else {
        $outcome = 'FAIL'
    }
} finally {
    Remove-Item Env:MESH_DASHBOARD_SECURITY_ROOT -ErrorAction SilentlyContinue
    Remove-Item Env:MESH_DASHBOARD_SECURITY_DRIVER -ErrorAction SilentlyContinue
    Remove-Item Env:MESH_DASHBOARD_SECURITY_EDGE -ErrorAction SilentlyContinue
    Remove-Item Env:MESH_DASHBOARD_SECURITY_PROFILE -ErrorAction SilentlyContinue
    if ($junction -and (Test-Path -LiteralPath $junction)) {
        $item = Get-Item -Force -LiteralPath $junction
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            [IO.Directory]::Delete($junction, $false)
        }
    }
    if ($outside -and (Test-Path -LiteralPath (Join-Path $outside 'must-survive.txt'))) {
        $still = [IO.File]::ReadAllText((Join-Path $outside 'must-survive.txt'))
        if ($still -cne $sentinel -and $null -eq $reason) {
            $reason = 'outside sentinel changed during cleanup'
            $outcome = 'FAIL'
            $cases.junction = 'FAIL'
        }
    }
    if ($workspace) {
        try { Remove-ProcessFixtureWorkspace $workspace } catch {
            if ($null -eq $reason) {
                $reason = $_.Exception.Message
                $outcome = 'FAIL'
            }
        }
    }
    Pop-Location
}

Write-Report -Outcome $outcome -Reason $reason
if ($outcome -eq 'PASS') { exit 0 }
exit 1
