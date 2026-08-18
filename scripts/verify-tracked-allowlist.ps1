[CmdletBinding()]
param(
    [string[]]$IndexPaths
)

$ErrorActionPreference = "Stop"

function Test-AllowedTrackedPath {
    param(
        [Parameter(Mandatory)] [string]$Candidate,
        [Parameter(Mandatory)] [string[]]$Patterns
    )

    foreach ($pattern in $Patterns) {
        if ($Candidate -like $pattern) {
            return $true
        }
    }

    return $false
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$allowlistPath = Join-Path $repositoryRoot "config/tracked-paths.txt"
$allowed = @(Get-Content -LiteralPath $allowlistPath |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith("#") })
$requiredPatterns = @(
    "config/**",
    "crates/**",
    "packages/**",
    "plugins/codex-agent-mesh/**",
    "protocol/**",
    "scripts/**",
    "tests/**"
)
$sourceRoots = @(
    "config",
    "crates",
    "packages",
    "plugins/codex-agent-mesh",
    "protocol",
    "scripts",
    "tests"
)
$requiredRootFiles = @(
    ".editorconfig",
    ".gitattributes",
    ".gitignore",
    ".prettierignore",
    "Cargo.lock",
    "Cargo.toml",
    "eslint.config.mjs",
    "README.md",
    "package-lock.json",
    "package.json",
    "rust-toolchain.toml"
)

if ($allowed.Count -eq 0) {
    throw "Tracked-path allowlist is empty: $allowlistPath"
}
foreach ($pattern in $allowed) {
    if ([System.IO.Path]::IsPathRooted($pattern) -or $pattern.Contains("..") -or $pattern.Contains("\")) {
        throw "Tracked-path allowlist contains an unsafe path pattern: $pattern"
    }
}
foreach ($pattern in $requiredPatterns) {
    if ($allowed -notcontains $pattern) {
        throw "Tracked-path allowlist omits required product root pattern: $pattern"
    }
}
foreach ($path in $requiredRootFiles) {
    if ($allowed -notcontains $path) {
        throw "Tracked-path allowlist omits required root file: $path"
    }
    if (-not (Test-Path -LiteralPath (Join-Path $repositoryRoot $path) -PathType Leaf)) {
        throw "Required root file is missing: $path"
    }
}

if ($PSBoundParameters.ContainsKey("IndexPaths")) {
    $indexedPaths = $IndexPaths
}
else {
    $indexedPaths = @(git -C $repositoryRoot ls-files)
}
$invalidIndexPaths = @($indexedPaths | Where-Object {
    $candidate = $_.Replace("\", "/")
    [System.IO.Path]::IsPathRooted($_) -or
    $_.Contains("\") -or
    ($candidate -split "/" | Where-Object { $_ -in @("", ".", "..") })
})
if ($invalidIndexPaths.Count -gt 0) {
    throw "Git index contains unsafe path(s):`n$($invalidIndexPaths -join "`n")"
}
$unexpectedIndexedPaths = @($indexedPaths | Where-Object {
    -not (Test-AllowedTrackedPath -Candidate $_ -Patterns $allowed)
})
if ($unexpectedIndexedPaths.Count -gt 0) {
    throw "Git index contains paths outside config/tracked-paths.txt:`n$($unexpectedIndexedPaths -join "`n")"
}

$candidates = [System.Collections.Generic.List[string]]::new()
foreach ($root in $sourceRoots) {
    $rootPath = Join-Path $repositoryRoot $root
    if (-not (Test-Path -LiteralPath $rootPath -PathType Container)) {
        throw "Required product source root is missing: $root"
    }
    if ((Get-Item -LiteralPath $rootPath).Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        throw "Product source root must not be a reparse point: $root"
    }
    $reparsePoints = @(Get-ChildItem -LiteralPath $rootPath -Recurse -Force |
        Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint })
    if ($reparsePoints.Count -gt 0) {
        throw "Product source roots must not contain reparse points: $($reparsePoints.FullName -join ", ")"
    }
    Get-ChildItem -LiteralPath $rootPath -File -Recurse -Force | ForEach-Object {
        $candidates.Add($_.FullName.Substring($repositoryRoot.Length + 1).Replace("\", "/"))
    }
}

$unexpected = @($candidates | Where-Object {
    -not (Test-AllowedTrackedPath -Candidate $_ -Patterns $allowed)
})
if ($unexpected.Count -gt 0) {
    throw "Product source paths outside config/tracked-paths.txt:`n$($unexpected -join "`n")"
}

Write-Output "Git index and product source inventory match config/tracked-paths.txt."
