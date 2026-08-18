[CmdletBinding()]
param(
    [string]$PluginRoot = "plugins/codex-agent-mesh"
)

$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$pluginPath = [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $PluginRoot))
$pluginRootPrefix = "$repositoryRoot$([System.IO.Path]::DirectorySeparatorChar)"

if (-not $pluginPath.StartsWith($pluginRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Plugin root must remain inside the repository: $PluginRoot"
}
if (-not (Test-Path -LiteralPath $pluginPath -PathType Container)) {
    throw "Plugin root does not exist: $PluginRoot"
}
if ((Get-Item -LiteralPath $pluginPath).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    throw "Plugin root must not be a reparse point: $PluginRoot"
}

$allowlistPath = Join-Path $repositoryRoot "config/plugin-package-paths.txt"
$allowed = @(Get-Content -LiteralPath $allowlistPath |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith("#") })
$required = $allowed

if ($allowed.Count -eq 0) {
    throw "Package allowlist is empty: $allowlistPath"
}
foreach ($path in $allowed) {
    if ([System.IO.Path]::IsPathRooted($path) -or $path.Contains("..") -or $path.Contains("\") -or $path.Contains("*") -or $path.Contains("?")) {
        throw "Package allowlist contains an unsafe exact path: $path"
    }
}
foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $pluginPath $path) -PathType Leaf)) {
        throw "Plugin is missing required source file: $path"
    }
}

$mcpManifest = Get-Content -Raw -LiteralPath (Join-Path $pluginPath ".mcp.json") | ConvertFrom-Json
$server = $mcpManifest.mcpServers."codex-agent-mesh"
if ($null -eq $server -or $server.command -ne "node" -or $server.cwd -ne ".") {
    throw "Plugin MCP entry must use node with cwd '.' resolved from the installed plugin root."
}
if ($server.args.Count -ne 1 -or $server.args[0] -ne "runtime/mcp-bridge/index.js") {
    throw "Plugin MCP entry must retain the deferred runtime bridge path."
}

$reparsePoints = @(Get-ChildItem -LiteralPath $pluginPath -Recurse -Force |
    Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint })
if ($reparsePoints.Count -gt 0) {
    throw "Plugin source must not contain reparse points: $($reparsePoints.FullName -join ", ")"
}

$actual = @(Get-ChildItem -LiteralPath $pluginPath -File -Recurse -Force |
    ForEach-Object { $_.FullName.Substring($pluginPath.Length + 1).Replace("\", "/") } |
    Sort-Object)
if (($actual -join "`n") -ne (($allowed | Sort-Object) -join "`n")) {
    throw "Plugin source inventory differs from config/plugin-package-paths.txt."
}

Write-Output "Plugin source inventory contains all required files and matches config/plugin-package-paths.txt."
