<#
.SYNOPSIS
Spawn mesh-fake-adapter with a grandchild, kill the Job Object, prove the tree is gone.

.DESCRIPTION
This is the OS-level M4 process-tree gate. It builds the fake adapter, assigns
it to the existing non-breakaway kill-on-close job harness, waits until a
grandchild exists, then closes the job. Both PIDs must disappear.
#>
[CmdletBinding()]
param(
    [string]$FakeAdapterPath,
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$fixtureRoot = Join-Path $repositoryRoot 'tests\process-fixtures\scheduled-job'
$startedAt = [DateTimeOffset]::UtcNow
$outcome = 'FAIL'
$reason = $null
$evidence = [ordered]@{}
$workRoot = $null

function ConvertTo-WindowsCommandLineArgument {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (2 * $slashes + 1)))
            [void]$builder.Append('"')
        } else {
            if ($slashes) { [void]$builder.Append(('\' * $slashes)) }
            [void]$builder.Append($character)
        }
        $slashes = 0
    }
    if ($slashes) { [void]$builder.Append(('\' * (2 * $slashes))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Get-MeshFakeAdapterPath {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [string]$FakeAdapterPath,
        [switch]$SkipBuild
    )
    if ($FakeAdapterPath) {
        return (Resolve-Path -LiteralPath $FakeAdapterPath -ErrorAction Stop).Path
    }
    $candidates = @(
        (Join-Path $RepositoryRoot 'target\debug\mesh-fake-adapter.exe'),
        (Join-Path $RepositoryRoot 'target\mesh-fake-adapter-test\debug\mesh-fake-adapter.exe')
    )
    if (-not $SkipBuild) {
        $isolated = Join-Path $RepositoryRoot 'target\mesh-fake-adapter-test'
        & cargo build -p mesh-fake-adapter --manifest-path (Join-Path $RepositoryRoot 'Cargo.toml') --offline --target-dir $isolated
        if ($LASTEXITCODE -ne 0) {
            & cargo build -p mesh-fake-adapter --manifest-path (Join-Path $RepositoryRoot 'Cargo.toml') --target-dir $isolated
        }
        if ($LASTEXITCODE -ne 0) { throw 'mesh-fake-adapter build failed' }
        $candidates = @(
            (Join-Path $isolated 'debug\mesh-fake-adapter.exe')
        ) + $candidates
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw 'mesh-fake-adapter.exe was not found'
}

function Wait-ChildProcessId {
    param([Parameter(Mandatory)][int]$ParentProcessId, [int]$TimeoutMs = 8000)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline) {
        $children = @(Get-CimInstance -ClassName Win32_Process -Filter "ParentProcessId = $ParentProcessId" -ErrorAction SilentlyContinue)
        if ($children.Count -gt 0) {
            return [int[]]@($children | ForEach-Object { [int]$_.ProcessId })
        }
        Start-Sleep -Milliseconds 50
    }
    throw "fake-adapter pid $ParentProcessId never spawned a grandchild"
}

function Test-ProcessGone {
    param([Parameter(Mandatory)][int]$ProcessId, [int]$TimeoutMs = 5000)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline) {
        $alive = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        if (-not $alive) { return $true }
        Start-Sleep -Milliseconds 50
    }
    return $false
}

try {
    if (-not $IsWindows) { throw 'WINDOWS_REQUIRED' }
    Add-Type -Path (Join-Path $fixtureRoot 'JobHarness.cs')
    $adapter = Get-MeshFakeAdapterPath -RepositoryRoot $repositoryRoot -FakeAdapterPath $FakeAdapterPath -SkipBuild:$SkipBuild
    $workRoot = Join-Path ([IO.Path]::GetTempPath()) ('mesh-process-tree-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($workRoot)
    $script = '[{"type":"spawn_grandchild"},{"type":"hang"}]'
    $commandLine = @(
        (ConvertTo-WindowsCommandLineArgument $adapter),
        '--json',
        (ConvertTo-WindowsCommandLineArgument $script)
    ) -join ' '

    try { $job = [MeshKillOnCloseJob]::Launch($adapter, $commandLine, $workRoot) }
    catch [ComponentModel.Win32Exception] { throw "job assignment failed: $($_.Exception.Message)" }

    try {
        $parentPid = [int]$job.ProcessId
        $evidence.parent_pid = $parentPid
        $evidence.adapter = $adapter
        $children = Wait-ChildProcessId -ParentProcessId $parentPid
        $evidence.grandchild_pids = @($children)
        $activeBefore = @($job.ActiveProcessIds())
        $evidence.job_pids_before_close = $activeBefore
        if ($activeBefore -notcontains $parentPid) { throw 'parent was not a job member before close' }
        foreach ($childPid in $children) {
            if ($activeBefore -notcontains $childPid) { throw "grandchild $childPid was not a job member before close" }
        }
        $job.CloseJob()
        $evidence.job_closed = $true
        if (-not (Test-ProcessGone -ProcessId $parentPid)) { throw "parent pid $parentPid survived job close" }
        foreach ($childPid in $children) {
            if (-not (Test-ProcessGone -ProcessId $childPid)) { throw "grandchild pid $childPid survived job close" }
        }
        $evidence.parent_gone = $true
        $evidence.grandchildren_gone = $true
        $outcome = 'PASS'
    } finally {
        if ($job) { $job.Dispose() }
    }
} catch {
    $reason = $_.Exception.Message
    if ($outcome -ne 'NOT_RUN') { $outcome = 'FAIL' }
} finally {
    if ($workRoot -and (Test-Path -LiteralPath $workRoot)) {
        try { Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction Stop } catch { }
    }
}

$report = [ordered]@{
    fixture = 'process-tree-v1'
    outcome = $outcome
    reason = $reason
    started_at_utc = $startedAt.ToString('O')
    duration_ms = [int]([DateTimeOffset]::UtcNow - $startedAt).TotalMilliseconds
    evidence = $evidence
}
$report | ConvertTo-Json -Depth 8
if ($outcome -eq 'PASS') { exit 0 }
exit 1
