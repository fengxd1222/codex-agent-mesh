[CmdletBinding()]
param(
    [string]$StageDirectory = "release/codex-agent-mesh",
    [switch]$TemporaryStage,
    [switch]$SkipBuild,
    [string]$PrebuiltSignedRuntime,
    [switch]$Release
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Get-RepoPath([string]$Path) {
    if ([System.IO.Path]::IsPathRooted($Path)) { return [System.IO.Path]::GetFullPath($Path) }
    [System.IO.Path]::GetFullPath((Join-Path $repositoryRoot $Path))
}

function Assert-SafeStage([string]$Path) {
    $releaseRoot = Get-RepoPath "release"
    $defaultStage = Get-RepoPath "release/codex-agent-mesh"
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
    $insideRelease = $Path.StartsWith("$releaseRoot$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::OrdinalIgnoreCase)
    $insideTemporary = $Path.StartsWith("$temporaryRoot$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::OrdinalIgnoreCase)
    if (-not $insideRelease -and (-not $TemporaryStage -or -not $insideTemporary)) {
        throw "StageDirectory must be below release/, or below the system temp root with -TemporaryStage."
    }
    if ($insideRelease -and $Path -ne $defaultStage) {
        throw "Release staging is fixed to release/codex-agent-mesh; custom release directories are never cleared."
    }
    $allowedRoot = if ($insideRelease) { $releaseRoot } else { $temporaryRoot }
    if ($Path -eq $allowedRoot -or $Path -eq $repositoryRoot) {
        throw "StageDirectory must name a child directory, never the repository or release root."
    }
    $cursor = $allowedRoot
    if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "The allowed staging root must not be a reparse point."
    }
    $relative = [IO.Path]::GetRelativePath($allowedRoot, $Path)
    foreach ($component in ($relative -split '[\\/]')) {
        if (-not $component) { continue }
        $cursor = Join-Path $cursor $component
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw "StageDirectory must not traverse a reparse point."
        }
    }
}

function Get-ArtifactFiles([string]$Root) {
    @(Get-ChildItem -LiteralPath $Root -File -Recurse -Force | ForEach-Object {
        $_.FullName.Substring($Root.Length + 1).Replace('\', '/')
    } | Sort-Object)
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$stage = Get-RepoPath $StageDirectory
Assert-SafeStage $stage
$releaseRoot = Get-RepoPath "release"
$defaultStage = Get-RepoPath "release/codex-agent-mesh"
$isReleaseChild = $stage.StartsWith("$releaseRoot$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::OrdinalIgnoreCase)
$stageMarker = "$stage.codex-agent-mesh-stage-owner"
$stageOwnedBefore = (Test-Path -LiteralPath $stageMarker -PathType Leaf) -and ((Get-Content -Raw -LiteralPath $stageMarker).Trim() -eq "codex-agent-mesh temporary stage")
$pin = $env:CODEX_AGENT_MESH_SIGNER_CERTIFICATE_SHA256
if ($Release) {
    if (-not $PrebuiltSignedRuntime -or $pin -notmatch "^[0-9a-fA-F]{64}$") {
        throw "Official release packaging requires -PrebuiltSignedRuntime and CODEX_AGENT_MESH_SIGNER_CERTIFICATE_SHA256."
    }
} elseif ($PrebuiltSignedRuntime) {
    throw "A prebuilt signed runtime is accepted only with explicit -Release."
}

if (-not $SkipBuild) {
    & npm run build --workspace packages/dashboard
    if (-not $?) { throw "Dashboard build failed." }
    & npm run build --workspace packages/mcp-bridge
    if (-not $?) { throw "Bridge build failed." }
    if (-not $Release) {
        & cargo build -p mesh-daemon --release --features unsigned-development
        if (-not $?) { throw "mesh-daemon development runtime build failed." }
    }
}

$bridgeDist = Get-RepoPath "packages/mcp-bridge/dist/bundle"
$daemonExe = if ($PrebuiltSignedRuntime) { [IO.Path]::GetFullPath($PrebuiltSignedRuntime) } else { Get-RepoPath "target/release/mesh-daemon.exe" }
if (-not (Test-Path -LiteralPath $bridgeDist -PathType Container)) { throw "Bridge dist is absent: $bridgeDist" }
if (-not (Test-Path -LiteralPath $daemonExe -PathType Leaf)) { throw "Release executable is absent: $daemonExe" }
$expectedBridgeFiles = @("index.js", "native-transport.js", "package.json", "protocol/v1/schema.json")
$actualBridgeFiles = @(Get-ChildItem -LiteralPath $bridgeDist -File -Recurse -Force | ForEach-Object {
    if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Bridge dist contains a reparse point." }
    $_.FullName.Substring($bridgeDist.Length + 1).Replace('\', '/')
} | Sort-Object)
if (($actualBridgeFiles -join "`n") -ne (($expectedBridgeFiles | Sort-Object) -join "`n")) {
    throw "Bridge dist inventory is not the exact packaged runtime inventory."
}
if ($Release) {
    $signature = Get-AuthenticodeSignature -LiteralPath $daemonExe
    $certificate = $signature.SignerCertificate
    if ($signature.Status -ne "Valid" -or $null -eq $certificate) { throw "Official release runtime must have a valid Authenticode signature." }
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $actualPin = [Convert]::ToHexString($hasher.ComputeHash($certificate.RawData)) } finally { $hasher.Dispose() }
    if ($actualPin -ne $pin.ToUpperInvariant()) { throw "Official release runtime signer certificate does not match CODEX_AGENT_MESH_SIGNER_CERTIFICATE_SHA256." }
}

if (Test-Path -LiteralPath $stage) {
    if (-not $stageOwnedBefore) {
        throw "Refusing to clear an existing stage without this script's ownership marker."
    }
    if ((Get-Item -LiteralPath $stage).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "StageDirectory must not be a reparse point." }
    $stageReparsePoints = @(Get-ChildItem -LiteralPath $stage -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
    if ($stageReparsePoints.Count -gt 0) { throw "Refusing to clear a stage containing reparse points." }
    Remove-Item -LiteralPath $stage -Recurse -Force
}
[void](New-Item -ItemType Directory -Force -Path $stage)
[IO.File]::WriteAllText($stageMarker, "codex-agent-mesh temporary stage`n", (New-Object Text.UTF8Encoding($false)))
$plugin = Get-RepoPath "plugins/codex-agent-mesh"
foreach ($relative in @(
    ".mcp.json",
    ".codex-plugin/plugin.json",
    "skills/codex-agent-mesh/SKILL.md",
    "skills/codex-agent-mesh/references/install-and-configure.md"
)) {
    $destination = Join-Path $stage $relative
    [void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination))
    Copy-Item -LiteralPath (Join-Path $plugin $relative) -Destination $destination -Force
}
foreach ($relative in @("index.js", "native-transport.js", "package.json", "protocol/v1/schema.json")) {
    $destination = Join-Path $stage "runtime/mcp-bridge/$relative"
    [void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination))
    Copy-Item -LiteralPath (Join-Path $bridgeDist $relative) -Destination $destination -Force
}
$runtimeDestination = Join-Path $stage "bin/windows-x64/mesh-daemon.exe"
[void](New-Item -ItemType Directory -Force -Path (Split-Path -Parent $runtimeDestination))
Copy-Item -LiteralPath $daemonExe -Destination $runtimeDestination -Force
$metadata = [ordered]@{
    formatVersion = 1
    runtimeTrust = if ($Release) { "official-signed" } else { "development-unsigned" }
    runtimeSource = if ($PrebuiltSignedRuntime) { "prebuilt-signed-runtime" } else { "local-release-build" }
    signerCertificateSha256 = if ($Release) { $pin.ToLowerInvariant() } else { $null }
}
[IO.File]::WriteAllText((Join-Path $stage "ARTIFACT-METADATA.json"), ($metadata | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))

$pluginManifest = Get-Content -Raw -LiteralPath (Join-Path $stage ".codex-plugin/plugin.json") | ConvertFrom-Json
$sbomComponents = @(Get-ArtifactFiles $stage | ForEach-Object {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $stage $_)).Hash.ToLowerInvariant()
    [ordered]@{
        type = "file"
        "bom-ref" = "file:$_"
        name = $_
        hashes = @([ordered]@{ alg = "SHA-256"; content = $hash })
    }
})
$sbom = [ordered]@{
    bomFormat = "CycloneDX"
    specVersion = "1.5"
    version = 1
    metadata = [ordered]@{
        component = [ordered]@{
            type = "application"
            "bom-ref" = "application:codex-agent-mesh"
            name = $pluginManifest.name
            version = $pluginManifest.version
        }
    }
    components = $sbomComponents
}
[IO.File]::WriteAllText((Join-Path $stage "SBOM.cdx.json"), ($sbom | ConvertTo-Json -Depth 8 -Compress), (New-Object Text.UTF8Encoding($false)))

$hashLines = @(Get-ArtifactFiles $stage | ForEach-Object {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $stage $_)).Hash.ToLowerInvariant()
    "$hash  $_"
})
[IO.File]::WriteAllLines((Join-Path $stage "SHA256SUMS"), $hashLines, (New-Object Text.UTF8Encoding($false)))

# ZipArchive with fixed timestamp, sorted entries and no compression is byte-stable on a fixed .NET runtime.
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zipPath = "$stage.zip"
if (Test-Path -LiteralPath $zipPath) {
    if (-not $stageOwnedBefore) {
        throw "Refusing to replace an existing stage zip without this script's ownership marker."
    }
    $zipItem = Get-Item -LiteralPath $zipPath
    if (-not $zipItem.PSIsContainer -and -not ($zipItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Remove-Item -LiteralPath $zipPath -Force
    } else {
        throw "Refusing to replace a non-regular or reparse zip target."
    }
}
$stream = [IO.File]::Open($zipPath, [IO.FileMode]::CreateNew)
try {
    $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $false)
    try {
        foreach ($relative in (Get-ArtifactFiles $stage | Sort-Object)) {
            $entry = $archive.CreateEntry($relative, [IO.Compression.CompressionLevel]::NoCompression)
            $entry.LastWriteTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
            $input = [IO.File]::OpenRead((Join-Path $stage $relative))
            try { $output = $entry.Open(); try { $input.CopyTo($output) } finally { $output.Dispose() } } finally { $input.Dispose() }
        }
    } finally { $archive.Dispose() }
} finally { $stream.Dispose() }

& (Join-Path $PSScriptRoot "verify-plugin-artifact.ps1") -ArtifactRoot $stage
if (-not $?) { throw "Built artifact did not verify." }
& node (Join-Path $PSScriptRoot "test-plugin-artifact-runtime.mjs") $stage
if (-not $?) { throw "Built artifact runtime layout smoke test failed." }
$label = if ($Release) { "official-signed artifact" } else { "development-unsigned artifact (not an official release)" }
Write-Output "Plugin $label staged at $stage; deterministic zip written to $zipPath"
