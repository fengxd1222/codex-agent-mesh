[CmdletBinding()]
param(
    [switch]$Live
)

$ErrorActionPreference = "Stop"
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$fixture = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot "config/plugin-install-path-fixture.json") |
    ConvertFrom-Json
$manifest = Get-Content -Raw -LiteralPath (Join-Path $repositoryRoot "plugins/codex-agent-mesh/.mcp.json") |
    ConvertFrom-Json

if ($fixture.expectedServerCwd -ne "." -or
    $manifest.mcpServers."codex-agent-mesh".cwd -ne $fixture.expectedServerCwd) {
    throw "The MCP cwd contract must stay relative to the installed plugin root."
}
if (-not $Live) {
    Write-Output "Install-path contract is recorded; pass -Live to run the isolated packaged bridge smoke."
    exit 0
}

$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
$fixtureRoot = Join-Path $temporaryRoot ("codex-agent-mesh path fixture " + [guid]::NewGuid().ToString("N"))
$ownerMarker = Join-Path $fixtureRoot ".fixture-owner"
try {
    [void](New-Item -ItemType Directory -Path $fixtureRoot)
    [IO.File]::WriteAllText($ownerMarker, "codex-agent-mesh install-path fixture`n", (New-Object Text.UTF8Encoding($false)))
    $pluginRoot = Join-Path $fixtureRoot "Test User plugins\codex-agent-mesh"
    $callerCwd = Join-Path $fixtureRoot "Test User\Documents\different caller cwd"
    [void](New-Item -ItemType Directory -Force -Path $callerCwd)

    & (Join-Path $PSScriptRoot "package-plugin.ps1") -StageDirectory $pluginRoot -TemporaryStage
    if (-not $?) { throw "Packaging under the path-with-spaces fixture failed." }
    & node (Join-Path $PSScriptRoot "test-plugin-install-path-runtime.mjs") $pluginRoot $callerCwd
    if (-not $?) { throw "The packaged bridge failed from the different caller cwd." }
    Write-Output "Isolated path-with-spaces and different-caller-cwd fixture passed without starting the retained installation."
} finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        $resolved = [IO.Path]::GetFullPath($fixtureRoot)
        $insideTemporary = $resolved.StartsWith("$temporaryRoot$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::OrdinalIgnoreCase)
        $owned = (Test-Path -LiteralPath $ownerMarker -PathType Leaf) -and
            ((Get-Content -Raw -LiteralPath $ownerMarker).Trim() -eq "codex-agent-mesh install-path fixture")
        $reparse = @(Get-ChildItem -LiteralPath $fixtureRoot -Recurse -Force | Where-Object {
            $_.Attributes -band [IO.FileAttributes]::ReparsePoint
        })
        if (-not $insideTemporary -or -not $owned -or $reparse.Count -ne 0) {
            throw "Refusing unsafe install-path fixture cleanup."
        }
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}
