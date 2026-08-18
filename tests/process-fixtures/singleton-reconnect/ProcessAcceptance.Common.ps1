Set-StrictMode -Version Latest

$script:FixtureProtocol = "codex-agent-mesh-process-fixture-v1"
$script:MaximumDriverOutputBytes = 1MB
$script:MaximumDriverErrorBytes = 64KB
$script:MeshDaemonLibTestCatalogue = $null
$script:FixtureDriverBindings = @{}

if ($null -eq ("CodexAgentMesh.ProcessFixtures.BoundedStreamReader" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CodexAgentMesh.ProcessFixtures {
    public sealed class BoundedCapture {
        public byte[] Bytes { get; }
        public bool Exceeded { get; }

        public BoundedCapture(byte[] bytes, bool exceeded) {
            Bytes = bytes;
            Exceeded = exceeded;
        }
    }

    public static class BoundedStreamReader {
        public static async Task<BoundedCapture> ReadAsync(
            Stream stream,
            int limit,
            Process owner,
            CancellationToken cancellationToken) {
            byte[] buffer = new byte[8192];
            using MemoryStream captured = new MemoryStream(Math.Min(limit + 1, 65536));
            while (true) {
                int read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0) {
                    return new BoundedCapture(captured.ToArray(), false);
                }
                int remaining = (limit + 1) - checked((int)captured.Length);
                if (read >= remaining) {
                    captured.Write(buffer, 0, remaining);
                    try { owner.Kill(true); } catch { }
                    return new BoundedCapture(captured.ToArray(), true);
                }
                captured.Write(buffer, 0, read);
            }
        }
    }
}
'@
}

function Get-RequiredProperty {
    param(
        [Parameter(Mandatory)] [object] $Object,
        [Parameter(Mandatory)] [string] $Name
    )

    if ($null -eq $Object -or -not ($Object.PSObject.Properties.Name -contains $Name)) {
        throw "Fixture response is missing required property '$Name'."
    }
    return $Object.$Name
}

function Assert-StringPattern {
    param(
        [Parameter(Mandatory)] [object] $Value,
        [Parameter(Mandatory)] [string] $Pattern,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($Value -isnot [string] -or $Value -cnotmatch $Pattern) {
        throw "Fixture returned an invalid $Label."
    }
}

function Get-RequiredString {
    param(
        [Parameter(Mandatory)] [object] $Object,
        [Parameter(Mandatory)] [string] $Name
    )

    $value = Get-RequiredProperty $Object $Name
    if ($value -isnot [string]) { throw "Fixture property '$Name' must be a JSON string." }
    return $value
}

function Get-RequiredBoolean {
    param(
        [Parameter(Mandatory)] [object] $Object,
        [Parameter(Mandatory)] [string] $Name
    )

    $value = Get-RequiredProperty $Object $Name
    if ($value -isnot [bool]) { throw "Fixture property '$Name' must be a JSON boolean." }
    return [bool]$value
}

function Get-RequiredArray {
    param(
        [Parameter(Mandatory)] [object] $Object,
        [Parameter(Mandatory)] [string] $Name
    )

    $value = Get-RequiredProperty $Object $Name
    if ($value -isnot [array]) { throw "Fixture property '$Name' must be a JSON array." }
    return [object[]]$value
}

function Assert-Integer {
    param(
        [Parameter(Mandatory)] [object] $Value,
        [Parameter(Mandatory)] [Int64] $Minimum,
        [Parameter(Mandatory)] [Int64] $Maximum,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($Value -isnot [byte] -and $Value -isnot [int16] -and $Value -isnot [int32] -and
        $Value -isnot [int64] -and $Value -isnot [uint16] -and $Value -isnot [uint32]) {
        throw "Fixture returned a non-integer $Label."
    }
    $integer = [Int64]$Value
    if ($integer -lt $Minimum -or $integer -gt $Maximum) {
        throw "Fixture returned an out-of-range $Label."
    }
    return $integer
}

function New-ProcessFixtureWorkspace {
    param([Parameter(Mandatory)] [string] $Prefix)

    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    Assert-PathHasNoReparseComponent $temporaryRoot
    $workspace = Join-Path $temporaryRoot ($Prefix + [guid]::NewGuid().ToString("N"))
    [void](New-Item -ItemType Directory -Path $workspace)
    $workspaceItem = Get-Item -Force -LiteralPath $workspace
    if (($workspaceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $workspaceItem.Parent.FullName.TrimEnd('\') -cne $temporaryRoot) {
        throw "Process-fixture workspace is not a direct, non-reparse temporary child."
    }
    Assert-PathHasNoReparseComponent $workspace
    $markerPath = Join-Path $workspace ".codex-agent-mesh-process-fixture"
    $markerBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($script:FixtureProtocol)
    $markerStream = $null
    try {
        $markerStream = [IO.FileStream]::new(
            $markerPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        $markerStream.Write($markerBytes, 0, $markerBytes.Length)
        $markerStream.Flush($true)
    } catch {
        try { [IO.Directory]::Delete($workspace, $false) } catch { }
        throw
    } finally {
        if ($null -ne $markerStream) { $markerStream.Dispose() }
    }
    return [IO.Path]::GetFullPath($workspace)
}

function Read-BoundedStrictUtf8File {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [ValidateRange(1, 4096)] [int] $MaximumBytes
    )

    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        if ($stream.Length -lt 1 -or $stream.Length -gt $MaximumBytes) {
            throw "Ownership marker length is outside its bounded contract."
        }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -eq 0) { throw "Ownership marker ended before its declared length." }
            $offset += $read
        }
        if ($stream.ReadByte() -ne -1) { throw "Ownership marker grew during its bounded read." }
        return [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    } finally {
        $stream.Dispose()
    }
}

function Get-ValidatedWorkspaceDeletionPlan {
    param(
        [Parameter(Mandatory)] [string] $Workspace,
        [ValidateRange(1, 4096)] [int] $MaximumEntries = 4096,
        [ValidateRange(1, 32)] [int] $MaximumDepth = 32
    )

    $queue = [Collections.Generic.Queue[object]]::new()
    $queue.Enqueue([pscustomobject]@{ Path = $Workspace; Depth = 0 })
    $entries = [Collections.Generic.List[object]]::new()
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        $directory = Get-Item -Force -LiteralPath $current.Path -ErrorAction Stop
        if (-not $directory.PSIsContainer -or
            ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Workspace traversal encountered a reparse or non-directory node."
        }
        foreach ($child in $directory.EnumerateFileSystemInfos()) {
            if ($entries.Count -ge $MaximumEntries) {
                throw "Workspace cleanup exceeded its bounded entry count."
            }
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Workspace cleanup refused a descendant reparse point."
            }
            $childDepth = [int]$current.Depth + 1
            if ($childDepth -gt $MaximumDepth) {
                throw "Workspace cleanup exceeded its bounded depth."
            }
            $entry = [pscustomobject]@{
                Path = $child.FullName
                Depth = $childDepth
                Directory = [bool](($child.Attributes -band [IO.FileAttributes]::Directory) -ne 0)
            }
            $entries.Add($entry)
            if ($entry.Directory) { $queue.Enqueue([pscustomobject]@{ Path = $entry.Path; Depth = $childDepth }) }
        }
    }
    return @($entries)
}

function Remove-ProcessFixtureWorkspace {
    param([Parameter(Mandatory)] [string] $Workspace)

    if (-not (Test-Path -LiteralPath $Workspace -PathType Container)) { return }
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    Assert-PathHasNoReparseComponent $temporaryRoot
    Assert-PathHasNoReparseComponent $Workspace
    $targetItem = Get-Item -Force -LiteralPath $Workspace
    if (($targetItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not $targetItem.PSIsContainer -or
        $targetItem.Parent.FullName.TrimEnd('\') -cne $temporaryRoot) {
        throw "Refusing to delete a reparse or non-direct process-fixture workspace."
    }
    $resolved = $targetItem.FullName
    $marker = Join-Path $resolved ".codex-agent-mesh-process-fixture"
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        throw "Refusing to delete a process-fixture workspace without its exact marker."
    }
    $markerItem = Get-Item -Force -LiteralPath $marker
    if (($markerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $markerItem.PSIsContainer -or $markerItem.Directory.FullName -cne $resolved -or
        (Read-BoundedStrictUtf8File -Path $marker -MaximumBytes 128) -cne $script:FixtureProtocol) {
        throw "Refusing to delete a process-fixture directory that this run does not own."
    }
    $plan = @(Get-ValidatedWorkspaceDeletionPlan -Workspace $resolved -MaximumEntries 4096 -MaximumDepth 32)
    foreach ($file in @($plan | Where-Object { -not $_.Directory })) {
        [IO.File]::Delete($file.Path)
    }
    foreach ($directory in @($plan | Where-Object { $_.Directory } | Sort-Object Depth -Descending)) {
        [IO.Directory]::Delete($directory.Path, $false)
    }
    [IO.Directory]::Delete($resolved, $false)
}

function Assert-PathHasNoReparseComponent {
    param([Parameter(Mandatory)] [string] $Path)

    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $rootItem = Get-Item -Force -LiteralPath $root -ErrorAction Stop
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Fixture path root is a reparse point."
    }
    $relative = $full.Substring($root.Length)
    $current = $root
    foreach ($component in $relative.Split([IO.Path]::DirectorySeparatorChar, [StringSplitOptions]::RemoveEmptyEntries)) {
        $current = Join-Path $current $component
        $item = Get-Item -Force -LiteralPath $current -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Fixture driver path contains a reparse component."
        }
    }
}

function Resolve-FixtureDriver {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $ExpectedSha256
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    Assert-StringPattern $ExpectedSha256 '^[0-9a-f]{64}$' "fixture driver digest"
    if (-not [IO.Path]::IsPathFullyQualified($Path)) { throw "Fixture driver path must be absolute." }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Fixture driver does not exist: $Path"
    }
    $full = [IO.Path]::GetFullPath($Path)
    Assert-PathHasNoReparseComponent $full
    $resolved = (Resolve-Path -LiteralPath $full).Path
    if ($resolved -cne $full) { throw "Fixture driver path did not round-trip canonically." }
    $actual = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $ExpectedSha256) { throw "Fixture driver digest binding failed." }
    $script:FixtureDriverBindings[$resolved] = $ExpectedSha256
    return $resolved
}

function Assert-StrictJsonElement {
    param(
        [Parameter(Mandatory)] [Text.Json.JsonElement] $Element,
        [Parameter(Mandatory)] [string] $Path
    )

    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) { throw "Fixture JSON contains duplicate key '$($property.Name)' at $Path." }
            Assert-StrictJsonElement -Element $property.Value -Path "$Path.$($property.Name)"
        }
    } elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        $index = 0
        foreach ($item in $Element.EnumerateArray()) {
            Assert-StrictJsonElement -Element $item -Path "$Path[$index]"
            $index++
        }
    }
}

function Invoke-FixtureDriver {
    param(
        [Parameter(Mandatory)] [string] $DriverPath,
        [Parameter(Mandatory)] [string] $Action,
        [Parameter(Mandatory)] [hashtable] $Input,
        [Parameter(Mandatory)] [string] $Workspace,
        [ValidateRange(1, 300)] [int] $TimeoutSeconds = 30
    )

    if (-not $script:FixtureDriverBindings.ContainsKey($DriverPath)) {
        throw "Fixture driver was not admitted through an independent digest binding."
    }
    Assert-PathHasNoReparseComponent $DriverPath
    $invocationDigest = (Get-FileHash -LiteralPath $DriverPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($invocationDigest -cne $script:FixtureDriverBindings[$DriverPath]) {
        throw "Fixture driver bytes changed after admission."
    }

    $token = [guid]::NewGuid().ToString("N")
    $inputPath = Join-Path $Workspace ("driver-input-{0}.json" -f $token)
    if ($Input.ContainsKey("fixture_invocation_token")) { throw "Caller cannot select the fixture invocation token." }
    $payload = @{}
    foreach ($key in $Input.Keys) { $payload[$key] = $Input[$key] }
    $payload.fixture_invocation_token = $token
    $json = $payload | ConvertTo-Json -Depth 30 -Compress
    [IO.File]::WriteAllText($inputPath, $json, [Text.UTF8Encoding]::new($false))

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    if ([IO.Path]::GetExtension($DriverPath) -ieq ".ps1") {
        $pwsh = (Get-Command pwsh -ErrorAction Stop).Source
        $startInfo.FileName = $pwsh
        foreach ($argument in @("-NoProfile", "-NonInteractive", "-File", $DriverPath)) {
            [void]$startInfo.ArgumentList.Add($argument)
        }
    } else {
        $startInfo.FileName = $DriverPath
    }
    foreach ($argument in @("--protocol", $script:FixtureProtocol, "--action", $Action, "--input", $inputPath)) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.WorkingDirectory = $Workspace

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $captureCancellation = [Threading.CancellationTokenSource]::new(($TimeoutSeconds + 2) * 1000)
    try {
        if (-not $process.Start()) { throw "Fixture driver could not be started." }
        $stdoutTask = [CodexAgentMesh.ProcessFixtures.BoundedStreamReader]::ReadAsync(
            $process.StandardOutput.BaseStream, $script:MaximumDriverOutputBytes, $process, $captureCancellation.Token)
        $stderrTask = [CodexAgentMesh.ProcessFixtures.BoundedStreamReader]::ReadAsync(
            $process.StandardError.BaseStream, $script:MaximumDriverErrorBytes, $process, $captureCancellation.Token)
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill($true) } catch { }
            if (-not $process.WaitForExit(1000)) { throw "Fixture driver could not be stopped within its cleanup bound." }
            throw "Fixture driver action '$Action' exceeded its bounded deadline."
        }
        $stdoutCapture = $stdoutTask.GetAwaiter().GetResult()
        $stderrCapture = $stderrTask.GetAwaiter().GetResult()
        if ($stdoutCapture.Exceeded -or $stderrCapture.Exceeded) {
            throw "Fixture driver action '$Action' exceeded its output budget."
        }
        $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
        $stdout = $strictUtf8.GetString($stdoutCapture.Bytes)
        $null = $strictUtf8.GetString($stderrCapture.Bytes)
        if ($process.ExitCode -ne 0) {
            throw "Fixture driver action '$Action' failed with exit $($process.ExitCode)."
        }
    } finally {
        $captureCancellation.Cancel()
        $captureCancellation.Dispose()
        $process.Dispose()
    }
    if ([string]::IsNullOrWhiteSpace($stdout)) {
        throw "Fixture driver action '$Action' returned no JSON evidence."
    }
    try {
        $document = [Text.Json.JsonDocument]::Parse($stdout, [Text.Json.JsonDocumentOptions]@{
            AllowTrailingCommas = $false
            CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
            MaxDepth = 40
        })
        try {
            if ($document.RootElement.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
                throw "Fixture JSON top level must be an object."
            }
            Assert-StrictJsonElement -Element $document.RootElement -Path '$'
        } finally { $document.Dispose() }
        $response = $stdout | ConvertFrom-Json -Depth 40
    } catch {
        throw "Fixture driver action '$Action' returned malformed JSON."
    }
    if ((Get-RequiredString $response "protocol") -cne $script:FixtureProtocol -or
        (Get-RequiredString $response "action") -cne $Action -or
        (Get-RequiredString $response "status") -cne "PASS" -or
        (Get-RequiredString $response "fixture_invocation_token") -cne $token) {
        throw "Fixture driver action '$Action' did not return a PASS v1 evidence object."
    }
    foreach ($echo in @("run_token", "case_token")) {
        if ($payload.ContainsKey($echo) -and (Get-RequiredString $response $echo) -cne [string]$payload[$echo]) {
            throw "Fixture driver action '$Action' did not echo its exact $echo."
        }
    }
    return $response
}

function Invoke-ExactCargoTest {
    param(
        [Parameter(Mandatory)] [string] $RepositoryRoot,
        [Parameter(Mandatory)] [string] $TestName
    )

    Push-Location -LiteralPath $RepositoryRoot
    try {
        if ($null -eq $script:MeshDaemonLibTestCatalogue) {
            $catalogueOutput = @(& cargo test -p mesh-daemon --lib -- --list 2>&1)
            if ($LASTEXITCODE -ne 0) { throw "Could not enumerate the mesh-daemon library test catalogue." }
            $catalogue = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($line in $catalogueOutput) {
                $text = $line.ToString()
                if ($text -match '^(.+): test$') { [void]$catalogue.Add($Matches[1]) }
            }
            if ($catalogue.Count -eq 0) { throw "The mesh-daemon library test catalogue was empty." }
            $script:MeshDaemonLibTestCatalogue = $catalogue
        }
        if (-not $script:MeshDaemonLibTestCatalogue.Contains($TestName)) {
            throw "Deterministic evidence test is absent from the exact library catalogue: $TestName"
        }
        & cargo test -p mesh-daemon --lib $TestName -- --exact --test-threads=1
        if ($LASTEXITCODE -ne 0) {
            throw "Deterministic evidence test failed: $TestName"
        }
    } finally {
        Pop-Location
    }
}

function Assert-ExactCargoTestRejectsMissing {
    param([Parameter(Mandatory)] [string] $RepositoryRoot)

    $missing = "__codex_agent_mesh_missing_test_$([guid]::NewGuid().ToString('N'))"
    try {
        Invoke-ExactCargoTest -RepositoryRoot $RepositoryRoot -TestName $missing
    } catch {
        if ($_.Exception.Message -like "*absent from the exact library catalogue*") { return }
        throw
    }
    throw "A nonexistent deterministic test name was accepted as a zero-test pass."
}

function Assert-PreflightEvidence {
    param(
        [Parameter(Mandatory)] [object] $Evidence,
        [Parameter(Mandatory)] [string[]] $Capabilities
    )

    if ((Get-RequiredString $Evidence "platform") -cne "windows-x64" -or
        -not (Get-RequiredBoolean $Evidence "interactive_user") -or
        (Get-RequiredString $Evidence "filesystem") -cne "NTFS") {
        throw "Fixture requires Windows x64, a logged-in interactive user, and local NTFS."
    }
    Assert-StringPattern (Get-RequiredString $Evidence "install_id") '^[0-9a-f]{32}$' "install ID"
    Assert-StringPattern (Get-RequiredString $Evidence "consumer_id") '^[0-9A-Za-z][0-9A-Za-z._:-]{0,127}$' "consumer ID"
    Assert-StringPattern (Get-RequiredString $Evidence "task_path") '^\\[^\\].+' "Scheduled Task path"
    Assert-StringPattern (Get-RequiredString $Evidence "task_definition_sha256") '^[0-9a-f]{64}$' "task definition digest"
    Assert-StringPattern (Get-RequiredString $Evidence "runtime_sha256") '^[0-9a-f]{64}$' "runtime digest"

    $runtimePath = Get-RequiredString $Evidence "runtime_path"
    if (-not [IO.Path]::IsPathFullyQualified($runtimePath) -or
        -not (Test-Path -LiteralPath $runtimePath -PathType Leaf)) {
        throw "Fixture runtime path is not an existing absolute file."
    }
    $observedDigest = (Get-FileHash -LiteralPath $runtimePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($observedDigest -cne $Evidence.runtime_sha256) {
        throw "Fixture runtime digest does not match the exact executable bytes."
    }
    $dataRoot = Get-RequiredString $Evidence "data_root"
    if (-not [IO.Path]::IsPathFullyQualified($dataRoot) -or
        -not (Test-Path -LiteralPath $dataRoot -PathType Container)) {
        throw "Fixture data root is not an existing absolute directory."
    }

    $available = @(Get-RequiredArray $Evidence "capabilities")
    if ($available.Where({ $_ -isnot [string] }).Count -ne 0 -or
        @($available | Sort-Object -Unique).Count -ne $available.Count) {
        throw "Fixture capabilities must be a unique JSON string array."
    }
    foreach ($capability in $Capabilities) {
        if ($available -cnotcontains $capability) {
            throw "Fixture driver does not implement required capability '$capability'."
        }
    }
    $launch = Get-RequiredProperty $Evidence "bridge_launch"
    $launchFile = Get-RequiredString $launch "file"
    if (-not [IO.Path]::IsPathFullyQualified($launchFile) -or
        -not (Test-Path -LiteralPath $launchFile -PathType Leaf)) {
        throw "Fixture bridge launch file is not an existing absolute file."
    }
    $arguments = @(Get-RequiredArray $launch "arguments")
    if ($arguments.Where({ $_ -isnot [string] }).Count -ne 0) {
        throw "Fixture bridge arguments must be an explicit string array."
    }
    Assert-StringPattern (Get-RequiredString $Evidence "bridge_sha256") '^[0-9a-f]{64}$' "bridge image digest"
    $bridgeDigest = (Get-FileHash -LiteralPath $launchFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($bridgeDigest -cne $Evidence.bridge_sha256) { throw "Fixture bridge image digest did not match its exact bytes." }
}

function Write-AcceptanceSummary {
    param([Parameter(Mandatory)] [hashtable] $Summary)
    Write-Output ($Summary | ConvertTo-Json -Depth 30 -Compress)
}

function Stop-OwnedProcessTree {
    param(
        [Parameter(Mandatory)] [Diagnostics.Process] $RootProcess,
        [Parameter(Mandatory)] [datetime] $ExpectedStartTimeUtc,
        [Parameter(Mandatory)] [string] $ExpectedImagePath
    )

    if ($RootProcess.HasExited) { return }
    $actualStart = $RootProcess.StartTime.ToUniversalTime()
    $actualImage = [IO.Path]::GetFullPath($RootProcess.MainModule.FileName)
    if ($actualStart -ne $ExpectedStartTimeUtc.ToUniversalTime() -or
        $actualImage -cne [IO.Path]::GetFullPath($ExpectedImagePath)) {
        throw "Refusing to terminate a wrapper whose captured process identity changed."
    }
    $RootProcess.Kill($true)
    if (-not $RootProcess.WaitForExit(1000)) { throw "Owned wrapper process tree did not stop within one second." }
}
