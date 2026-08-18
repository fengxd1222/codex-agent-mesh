[CmdletBinding()]
param([string]$ArtifactRoot = "release/codex-agent-mesh")

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$root = if ([IO.Path]::IsPathRooted($ArtifactRoot)) { [IO.Path]::GetFullPath($ArtifactRoot) } else { [IO.Path]::GetFullPath((Join-Path $repositoryRoot $ArtifactRoot)) }
if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "Artifact root does not exist: $ArtifactRoot" }
if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Artifact root must not be a reparse point." }

$expectedInventory = @(Get-Content -LiteralPath (Join-Path $repositoryRoot "config/plugin-artifact-paths.txt") | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("#") })
if ($expectedInventory.Count -eq 0) { throw "Artifact inventory is empty." }
foreach ($path in $expectedInventory) {
    if ([IO.Path]::IsPathRooted($path) -or $path.Contains("..") -or $path.Contains("\") -or $path.Contains("*") -or $path.Contains("?")) {
        throw "Artifact inventory contains an unsafe non-exact path: $path"
    }
}
$required = $expectedInventory

$forbidden = @("node_modules", ".claude", ".cursor", ".grok", ".kimi-code", ".pi", "target")
$items = @(Get-ChildItem -LiteralPath $root -Recurse -Force)
foreach ($item in $items) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Artifact contains reparse point: $($item.FullName)" }
}
$files = @(Get-ChildItem -LiteralPath $root -File -Recurse -Force | ForEach-Object { $_.FullName.Substring($root.Length + 1).Replace('\', '/') } | Sort-Object)
foreach ($path in $files) {
    $forbiddenSegments = @($path -split "/" | Where-Object { $forbidden -contains $_ })
    if ($forbiddenSegments.Count -gt 0) { throw "Artifact contains forbidden path segment: $path" }
}
foreach ($path in $required) { if ($files -notcontains $path) { throw "Artifact is missing required file: $path" } }
$actualInventory = $files -join "`n"
$declaredInventory = ($expectedInventory | Sort-Object) -join "`n"
if ($actualInventory -ne $declaredInventory) { throw "Artifact inventory differs from config/plugin-artifact-paths.txt." }

$plugin = Get-Content -Raw -LiteralPath (Join-Path $root ".codex-plugin/plugin.json") | ConvertFrom-Json
if ($plugin.name -ne "codex-agent-mesh" -or $plugin.mcpServers -ne "./.mcp.json" -or $plugin.skills -ne "./skills/") { throw "Plugin manifest does not match the packaged Codex contract." }
$mcp = Get-Content -Raw -LiteralPath (Join-Path $root ".mcp.json") | ConvertFrom-Json
$server = $mcp.mcpServers."codex-agent-mesh"
if ($null -eq $server -or $server.command -ne "node" -or $server.cwd -ne "." -or @($server.args).Count -ne 1 -or $server.args[0] -ne "runtime/mcp-bridge/index.js") { throw "MCP manifest does not point to the bundled bridge." }
$runtimePackage = Get-Content -Raw -LiteralPath (Join-Path $root "runtime/mcp-bridge/package.json") | ConvertFrom-Json
if ($runtimePackage.type -ne "module" -or $runtimePackage.private -ne $true) { throw "Bundled bridge must have an explicit private ESM package boundary." }
$metadata = Get-Content -Raw -LiteralPath (Join-Path $root "ARTIFACT-METADATA.json") | ConvertFrom-Json
if ($metadata.formatVersion -ne 1 -or @("development-unsigned", "official-signed") -notcontains $metadata.runtimeTrust) { throw "Artifact metadata has no recognized runtime trust declaration." }
$runtime = Join-Path $root "bin/windows-x64/mesh-daemon.exe"
$signature = Get-AuthenticodeSignature -LiteralPath $runtime
if ($metadata.runtimeTrust -eq "development-unsigned") {
    if ($signature.Status -ne "NotSigned" -or $null -ne $metadata.signerCertificateSha256) {
        throw "Development artifact must contain a genuinely unsigned runtime and no signer claim."
    }
} else {
    if ($metadata.signerCertificateSha256 -notmatch "^[0-9a-f]{64}$" -or $signature.Status -ne "Valid" -or $null -eq $signature.SignerCertificate) {
        throw "Official artifact has no valid pinned Authenticode identity."
    }
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $actualPin = [Convert]::ToHexString($hasher.ComputeHash($signature.SignerCertificate.RawData)).ToLowerInvariant() } finally { $hasher.Dispose() }
    if ($actualPin -ne $metadata.signerCertificateSha256) { throw "Official artifact signer certificate does not match metadata." }
}

$sbom = Get-Content -Raw -LiteralPath (Join-Path $root "SBOM.cdx.json") | ConvertFrom-Json
if ($sbom.bomFormat -ne "CycloneDX" -or $sbom.specVersion -ne "1.5" -or $sbom.version -ne 1) {
    throw "Artifact SBOM is not deterministic CycloneDX 1.5."
}
if ($sbom.metadata.component.type -ne "application" -or
    $sbom.metadata.component.'bom-ref' -ne "application:codex-agent-mesh" -or
    $sbom.metadata.component.name -ne $plugin.name -or
    $sbom.metadata.component.version -ne $plugin.version) {
    throw "Artifact SBOM metadata does not match the plugin manifest."
}
$sbomExpectedFiles = @($files | Where-Object { $_ -notin @("SBOM.cdx.json", "SHA256SUMS") } | Sort-Object)
$sbomComponents = @($sbom.components)
if ($sbomComponents.Count -ne $sbomExpectedFiles.Count) { throw "Artifact SBOM component count is incomplete." }
$sbomObserved = @{}
foreach ($component in $sbomComponents) {
    $componentProperties = @($component.PSObject.Properties.Name | Sort-Object)
    if (($componentProperties -join "`n") -ne ((@("bom-ref", "hashes", "name", "type") | Sort-Object) -join "`n") -or
        $component.type -ne "file" -or $component.'bom-ref' -ne "file:$($component.name)" -or
        $component.name -notin $sbomExpectedFiles -or $sbomObserved.ContainsKey($component.name)) {
        throw "Artifact SBOM contains an invalid or duplicate file component."
    }
    $hashes = @($component.hashes)
    if ($hashes.Count -ne 1 -or $hashes[0].alg -ne "SHA-256" -or $hashes[0].content -notmatch "^[0-9a-f]{64}$") {
        throw "Artifact SBOM contains an invalid file hash."
    }
    $actual = (Get-FileHash -LiteralPath (Join-Path $root $component.name) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $hashes[0].content) { throw "Artifact SBOM hash mismatch: $($component.name)" }
    $sbomObserved[$component.name] = $true
}
if ((@($sbomObserved.Keys | Sort-Object) -join "`n") -ne ($sbomExpectedFiles -join "`n")) {
    throw "Artifact SBOM inventory differs from the payload."
}

$lines = @(Get-Content -LiteralPath (Join-Path $root "SHA256SUMS"))
$expected = @{}
foreach ($line in $lines) {
    if ($line -notmatch "^([0-9a-f]{64})  ([^\\/].*)$") { throw "Invalid SHA256SUMS line: $line" }
    $relative = $Matches[2]
    if ($relative.Contains("..") -or $relative.Contains("\\")) { throw "Unsafe SHA256SUMS path: $relative" }
    if ($expected.ContainsKey($relative)) { throw "Duplicate SHA256SUMS path: $relative" }
    $expected[$relative] = $Matches[1]
}
$hashedFiles = @($files | Where-Object { $_ -ne "SHA256SUMS" })
$expectedHashInventory = @($expected.Keys | Sort-Object) -join "`n"
$actualHashInventory = @($hashedFiles | Sort-Object) -join "`n"
if ($expectedHashInventory -ne $actualHashInventory) { throw "SHA256SUMS inventory does not exactly match artifact files." }
foreach ($relative in $hashedFiles) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $root $relative) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected[$relative]) { throw "SHA256 mismatch: $relative" }
}
Write-Output "Plugin artifact verified: $root"
