[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot "ProcessAcceptance.Common.ps1")

function Write-FlushedMarker {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Value
    )

    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($Value)
    $stream = [IO.FileStream]::new($Path, [IO.FileMode]::Truncate, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
}

$outside = $null
$junctionWorkspace = $null
$driftWorkspace = $null
$junctionPath = $null
try {
    $outside = New-ProcessFixtureWorkspace "mesh-cleanup-outside-"
    $valuable = Join-Path $outside "must-survive.txt"
    [IO.File]::WriteAllText($valuable, "preserve", [Text.UTF8Encoding]::new($false, $true))

    $junctionWorkspace = New-ProcessFixtureWorkspace "mesh-cleanup-junction-"
    $junctionPath = Join-Path $junctionWorkspace "descendant-junction"
    [void](New-Item -ItemType Junction -Path $junctionPath -Target $outside)
    $junctionRejected = $false
    try { Remove-ProcessFixtureWorkspace $junctionWorkspace } catch { $junctionRejected = $true }
    if (-not $junctionRejected -or
        -not (Test-Path -LiteralPath $junctionWorkspace -PathType Container) -or
        -not (Test-Path -LiteralPath $junctionPath -PathType Container) -or
        -not (Test-Path -LiteralPath $valuable -PathType Leaf) -or
        (Get-Content -Raw -LiteralPath $valuable) -cne "preserve") {
        throw "Descendant junction cleanup was not rejected and preserved fail-closed."
    }

    $driftWorkspace = New-ProcessFixtureWorkspace "mesh-cleanup-marker-drift-"
    $driftMarker = Join-Path $driftWorkspace ".codex-agent-mesh-process-fixture"
    Write-FlushedMarker -Path $driftMarker -Value "drifted-marker"
    $driftRejected = $false
    try { Remove-ProcessFixtureWorkspace $driftWorkspace } catch { $driftRejected = $true }
    if (-not $driftRejected -or
        -not (Test-Path -LiteralPath $driftWorkspace -PathType Container) -or
        (Read-BoundedStrictUtf8File -Path $driftMarker -MaximumBytes 128) -cne "drifted-marker") {
        throw "Marker drift cleanup was not rejected and preserved fail-closed."
    }

    Write-Output '{"suite":"process-fixture-cleanup","status":"PASS","descendant_junction_preserved":true,"marker_drift_preserved":true}'
} finally {
    if ($null -ne $junctionPath -and (Test-Path -LiteralPath $junctionPath)) {
        $junction = Get-Item -Force -LiteralPath $junctionPath
        if (($junction.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
            throw "Adversarial cleanup test refused to remove a non-reparse junction path."
        }
        [IO.Directory]::Delete($junctionPath, $false)
    }
    if ($null -ne $driftWorkspace -and (Test-Path -LiteralPath $driftWorkspace -PathType Container)) {
        Write-FlushedMarker -Path (Join-Path $driftWorkspace ".codex-agent-mesh-process-fixture") -Value $script:FixtureProtocol
        Remove-ProcessFixtureWorkspace $driftWorkspace
    }
    if ($null -ne $junctionWorkspace -and (Test-Path -LiteralPath $junctionWorkspace -PathType Container)) {
        Remove-ProcessFixtureWorkspace $junctionWorkspace
    }
    if ($null -ne $outside -and (Test-Path -LiteralPath $outside -PathType Container)) {
        Remove-ProcessFixtureWorkspace $outside
    }
}
