[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ("codex-agent-mesh-artifact-" + [guid]::NewGuid().ToString("N"))
function Assert-Rejected([string]$Artifact, [string]$Message) {
    $accepted = $false
    try { & (Join-Path $PSScriptRoot "verify-plugin-artifact.ps1") -ArtifactRoot $Artifact; $accepted = $true } catch { }
    if ($accepted) { throw $Message }
}
function Assert-PackagingRejected([string]$Stage, [string]$Message) {
    $accepted = $false
    try { & (Join-Path $PSScriptRoot "package-plugin.ps1") -StageDirectory $Stage -TemporaryStage -SkipBuild; $accepted = $true } catch { }
    if ($accepted) { throw $Message }
}
try {
    $artifact = Join-Path $fixtureRoot "artifact"
    $paths = @(".codex-plugin", "skills/codex-agent-mesh", "runtime/mcp-bridge/protocol/v1", "bin/windows-x64")
    foreach ($path in $paths) { [void](New-Item -ItemType Directory -Force -Path (Join-Path $artifact $path)) }
    Copy-Item (Join-Path $repositoryRoot "plugins/codex-agent-mesh/.codex-plugin/plugin.json") (Join-Path $artifact ".codex-plugin/plugin.json")
    Copy-Item (Join-Path $repositoryRoot "plugins/codex-agent-mesh/.mcp.json") (Join-Path $artifact ".mcp.json")
    Set-Content -LiteralPath (Join-Path $artifact "skills/codex-agent-mesh/SKILL.md") -Value "fixture" -NoNewline
    [void](New-Item -ItemType Directory -Force -Path (Join-Path $artifact "skills/codex-agent-mesh/references"))
    Set-Content -LiteralPath (Join-Path $artifact "skills/codex-agent-mesh/references/install-and-configure.md") -Value "fixture" -NoNewline
    Set-Content -LiteralPath (Join-Path $artifact "runtime/mcp-bridge/index.js") -Value "fixture" -NoNewline
    Set-Content -LiteralPath (Join-Path $artifact "runtime/mcp-bridge/native-transport.js") -Value "fixture" -NoNewline
    Set-Content -LiteralPath (Join-Path $artifact "runtime/mcp-bridge/package.json") -Value '{"private":true,"type":"module"}' -NoNewline
    Copy-Item (Join-Path $repositoryRoot "protocol/v1/schema.json") (Join-Path $artifact "runtime/mcp-bridge/protocol/v1/schema.json")
    $runtimeFixture = Join-Path $repositoryRoot "target/release/mesh-daemon.exe"
    if (-not (Test-Path -LiteralPath $runtimeFixture -PathType Leaf)) {
        throw "Artifact fixture requires the unsigned release runtime; run plugin:package first."
    }
    Copy-Item -LiteralPath $runtimeFixture -Destination (Join-Path $artifact "bin/windows-x64/mesh-daemon.exe")
    Set-Content -LiteralPath (Join-Path $artifact "ARTIFACT-METADATA.json") -Value '{"formatVersion":1,"runtimeTrust":"development-unsigned","runtimeSource":"fixture","signerCertificateSha256":null}' -NoNewline
    $plugin = Get-Content -Raw -LiteralPath (Join-Path $artifact ".codex-plugin/plugin.json") | ConvertFrom-Json
    $sbomComponents = @(Get-ChildItem $artifact -File -Recurse | ForEach-Object {
        $relative = $_.FullName.Substring($artifact.Length + 1).Replace('\', '/')
        [ordered]@{
            type = "file"
            "bom-ref" = "file:$relative"
            name = $relative
            hashes = @([ordered]@{ alg = "SHA-256"; content = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() })
        }
    } | Sort-Object name)
    $sbom = [ordered]@{
        bomFormat = "CycloneDX"
        specVersion = "1.5"
        version = 1
        metadata = [ordered]@{ component = [ordered]@{ type = "application"; "bom-ref" = "application:codex-agent-mesh"; name = $plugin.name; version = $plugin.version } }
        components = $sbomComponents
    }
    $sbomJson = $sbom | ConvertTo-Json -Depth 8 -Compress
    [IO.File]::WriteAllText((Join-Path $artifact "SBOM.cdx.json"), $sbomJson, (New-Object Text.UTF8Encoding($false)))
    $files = @(Get-ChildItem $artifact -File -Recurse | ForEach-Object { $_.FullName.Substring($artifact.Length + 1).Replace('\', '/') } | Sort-Object)
    $lines = $files | ForEach-Object { "$( (Get-FileHash (Join-Path $artifact $_) -Algorithm SHA256).Hash.ToLowerInvariant() )  $_" }
    [IO.File]::WriteAllLines((Join-Path $artifact "SHA256SUMS"), $lines, (New-Object Text.UTF8Encoding($false)))
    & (Join-Path $PSScriptRoot "verify-plugin-artifact.ps1") -ArtifactRoot $artifact
    if (-not $?) { throw "Baseline fixture failed." }
    $tamperedSbom = $sbomJson | ConvertFrom-Json
    $tamperedSbom.components[0].hashes[0].content = "0" * 64
    [IO.File]::WriteAllText((Join-Path $artifact "SBOM.cdx.json"), ($tamperedSbom | ConvertTo-Json -Depth 8 -Compress), (New-Object Text.UTF8Encoding($false)))
    Assert-Rejected $artifact "Forged SBOM component hash was accepted."
    [IO.File]::WriteAllText((Join-Path $artifact "SBOM.cdx.json"), $sbomJson, (New-Object Text.UTF8Encoding($false)))
    Remove-Item (Join-Path $artifact "SBOM.cdx.json")
    Assert-Rejected $artifact "Missing SBOM fixture was accepted."
    [IO.File]::WriteAllText((Join-Path $artifact "SBOM.cdx.json"), $sbomJson, (New-Object Text.UTF8Encoding($false)))
    Remove-Item (Join-Path $artifact "runtime/mcp-bridge/index.js")
    Assert-Rejected $artifact "Missing runtime fixture was accepted."
    Set-Content -LiteralPath (Join-Path $artifact "runtime/mcp-bridge/index.js") -Value "fixture" -NoNewline
    Remove-Item (Join-Path $artifact "bin/windows-x64/mesh-daemon.exe")
    Assert-Rejected $artifact "Missing executable fixture was accepted."
    Copy-Item -LiteralPath $runtimeFixture -Destination (Join-Path $artifact "bin/windows-x64/mesh-daemon.exe")
    Set-Content -LiteralPath (Join-Path $artifact "extra.txt") -Value "bad" -NoNewline
    Assert-Rejected $artifact "Extra-file fixture was accepted."
    Remove-Item (Join-Path $artifact "extra.txt")
    New-Item -ItemType Directory -Force -Path (Join-Path $artifact "runtime/mcp-bridge/node_modules/cache") | Out-Null
    Set-Content -LiteralPath (Join-Path $artifact "runtime/mcp-bridge/node_modules/cache/evil.js") -Value "bad" -NoNewline
    Assert-Rejected $artifact "Nested runtime cache fixture was accepted."
    Remove-Item (Join-Path $artifact "runtime/mcp-bridge/node_modules") -Recurse -Force
    Remove-Item (Join-Path $artifact "ARTIFACT-METADATA.json")
    Assert-Rejected $artifact "Missing metadata fixture was accepted."
    Set-Content -LiteralPath (Join-Path $artifact "ARTIFACT-METADATA.json") -Value '{"formatVersion":1,"runtimeTrust":"invalid","runtimeSource":"fixture","signerCertificateSha256":null}' -NoNewline
    Assert-Rejected $artifact "Invalid metadata fixture was accepted."
    Set-Content -LiteralPath (Join-Path $artifact "ARTIFACT-METADATA.json") -Value '{"formatVersion":1,"runtimeTrust":"development-unsigned","runtimeSource":"fixture","signerCertificateSha256":null}' -NoNewline
    Set-Content -LiteralPath (Join-Path $artifact "runtime/mcp-bridge/index.js") -Value "drift" -NoNewline
    Assert-Rejected $artifact "Hash-drift fixture was accepted."
    $valuableStage = Join-Path $fixtureRoot "valuable-existing-stage"
    New-Item -ItemType Directory -Force -Path $valuableStage | Out-Null
    Set-Content -LiteralPath (Join-Path $valuableStage "must-survive.txt") -Value "preserve" -NoNewline
    Assert-PackagingRejected $valuableStage "Existing unowned temporary stage was deleted."
    if (-not (Test-Path -LiteralPath (Join-Path $valuableStage "must-survive.txt") -PathType Leaf)) { throw "Unowned stage content was not preserved." }
    $zipOnlyStage = Join-Path $fixtureRoot "default-stage-zip-boundary"
    $zipOnlyPath = "$zipOnlyStage.zip"
    Set-Content -LiteralPath $zipOnlyPath -Value "must-survive" -NoNewline
    Assert-PackagingRejected $zipOnlyStage "Existing unowned stage zip was replaced."
    if ((Get-Content -Raw -LiteralPath $zipOnlyPath) -ne "must-survive") { throw "Unowned stage zip was not preserved." }
    $deterministicStageA = Join-Path $fixtureRoot "deterministic-a"
    $deterministicStageB = Join-Path $fixtureRoot "deterministic-b"
    & (Join-Path $PSScriptRoot "package-plugin.ps1") -StageDirectory $deterministicStageA -TemporaryStage -SkipBuild
    if (-not $?) { throw "First deterministic packaging fixture failed." }
    & (Join-Path $PSScriptRoot "package-plugin.ps1") -StageDirectory $deterministicStageB -TemporaryStage -SkipBuild
    if (-not $?) { throw "Second deterministic packaging fixture failed." }
    $zipA = (Get-FileHash -LiteralPath "$deterministicStageA.zip" -Algorithm SHA256).Hash
    $zipB = (Get-FileHash -LiteralPath "$deterministicStageB.zip" -Algorithm SHA256).Hash
    if ($zipA -ne $zipB) { throw "Identical package inputs produced different zip bytes." }
    Write-Output "Plugin artifact fixture catches SBOM drift, missing runtime/executable, extra files/caches, metadata/hash drift, unowned stage deletion, and nondeterministic zip output."
} finally { if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force } }
