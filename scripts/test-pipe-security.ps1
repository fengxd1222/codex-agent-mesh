<#
.SYNOPSIS
Runs the unprivileged Windows named-pipe security matrix and writes bounded JSON evidence.

.DESCRIPTION
The default gate executes every available current-user test and records privileged
cross-user, LocalSystem, remote, and anonymous cases as NOT RUN. Release fixtures
may import those four cases explicitly. Each imported JSON document must contain:

  schema_version: 1
  case_id: cross-user | local-system | remote | anonymous
  outcome: PASS | FAIL
  observed_at_utc: an ISO-8601 round-trip timestamp
  harness_sha256: lower-case SHA-256 of the privileged fixture harness
  runtime_sha256, installation_sid, os_build, filesystem: exact local matches
  assertions: [{ id: <required assertion>, passed: true }]

Required assertion IDs are connection_rejected/router_calls_zero for cross-user
and LocalSystem, remote_connection_rejected/router_calls_zero for remote, and
anonymous_connection_rejected/router_calls_zero for anonymous. Only allowlisted
attestation fields are copied into the suite report; raw fixture content is not.
Every evidence path must be accompanied by two independently supplied lower-case
SHA-256 values: the exact evidence-file digest and the expected privileged
harness digest. The file is hashed before JSON parsing, and its harness_sha256
field must equal the independent harness expectation. For example,
-CrossUserEvidencePath requires -CrossUserExpectedEvidenceSha256 and
-CrossUserExpectedHarnessSha256; the LocalSystem, Remote, and Anonymous
parameters follow the same naming pattern.
Imported JSON must be exactly one object with the documented fields and exact
JSON value types. Duplicate/unknown keys, coercive strings, extra assertion
fields, and non-object roots are rejected.
#>
[CmdletBinding()]
param(
    [string]$RuntimePath,
    [string]$EvidencePath,
    [string]$CrossUserEvidencePath,
    [string]$LocalSystemEvidencePath,
    [string]$RemoteEvidencePath,
    [string]$AnonymousEvidencePath,
    [string]$CrossUserExpectedEvidenceSha256,
    [string]$CrossUserExpectedHarnessSha256,
    [string]$LocalSystemExpectedEvidenceSha256,
    [string]$LocalSystemExpectedHarnessSha256,
    [string]$RemoteExpectedEvidenceSha256,
    [string]$RemoteExpectedHarnessSha256,
    [string]$AnonymousExpectedEvidenceSha256,
    [string]$AnonymousExpectedHarnessSha256,
    [switch]$RequirePrivilegedEvidence,
    [switch]$RequireValidSignature,
    [ValidateRange(1, 1440)]
    [int]$MaxPrivilegedEvidenceAgeHours = 24,
    [ValidateRange(10, 900)]
    [int]$CommandTimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$startedAt = [DateTimeOffset]::UtcNow
$results = [Collections.Generic.List[object]]::new()
$privilegedResults = [Collections.Generic.List[object]]::new()
$fatalErrors = [Collections.Generic.List[string]]::new()
$maximumRuntimeBytes = 256MB

if ($null -eq ("PipeSecurityNativeMethods" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class PipeSecurityNativeMethods
{
    [StructLayout(LayoutKind.Sequential)]
    public struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);
}
'@
}

function Resolve-RepositoryPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) {
        return [IO.Path]::GetFullPath($Path)
    }
    return [IO.Path]::GetFullPath((Join-Path $repositoryRoot $Path))
}

function Invoke-BoundedProcess {
    param(
        [Parameter(Mandatory)] [string]$Executable,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [Parameter(Mandatory)] [int]$TimeoutSeconds
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.WorkingDirectory = $repositoryRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Environment["CARGO_TERM_COLOR"] = "never"
    foreach ($argument in $Arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    if (-not $process.Start()) {
        throw "Failed to start a required test process."
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $completed = $process.WaitForExit($TimeoutSeconds * 1000)
    if (-not $completed) {
        try { $process.Kill($true) } catch { $process.Kill() }
        $process.WaitForExit()
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $stopwatch.Stop()
    $exitCode = if ($completed) { $process.ExitCode } else { -1 }
    $process.Dispose()

    [pscustomobject]@{
        ExitCode = $exitCode
        TimedOut = -not $completed
        DurationMs = $stopwatch.ElapsedMilliseconds
        Stdout = $stdout
        Stderr = $stderr
    }
}

function Add-Result {
    param(
        [Parameter(Mandatory)] [string]$Id,
        [Parameter(Mandatory)] [string]$Status,
        [Parameter(Mandatory)] [string]$EvidenceClass,
        [string]$Package,
        [string]$ExactTest,
        [Nullable[int]]$ExitCode,
        [Nullable[long]]$DurationMs,
        [Parameter(Mandatory)] [string]$Assertion
    )
    $results.Add([pscustomobject]@{
        id = $Id
        status = $Status
        evidence_class = $EvidenceClass
        package = $Package
        exact_test = $ExactTest
        exit_code = $ExitCode
        duration_ms = $DurationMs
        assertion = $Assertion
    })
    $marker = if ($Status -eq "PASS") { "+" } else { "!" }
    Write-Host ("[{0}] {1}: {2}" -f $marker, $Id, $Status)
}

function Get-DriveEvidence([string]$Path) {
    $root = [IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path))
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "A filesystem root could not be resolved."
    }
    $drive = [IO.DriveInfo]::new($root)
    [pscustomobject]@{
        root = $root
        filesystem = $drive.DriveFormat
        drive_type = $drive.DriveType.ToString()
    }
}

function Get-HostEvidence {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity.User) {
        throw "The current Windows token has no user SID."
    }
    $version = [Environment]::OSVersion.Version
    $build = $version.Build.ToString([Globalization.CultureInfo]::InvariantCulture)
    $displayVersion = $null
    try {
        $windows = Get-ItemProperty -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        if ($windows.CurrentBuildNumber -match '^\d+$') {
            $build = [string]$windows.CurrentBuildNumber
            if ($null -ne $windows.UBR) {
                $build += "." + ([string]$windows.UBR)
            }
        }
        $displayVersion = [string]$windows.DisplayVersion
    } catch {
        # Environment.OSVersion is retained as the fail-closed fallback value.
    }
    [pscustomobject]@{
        os_build = $build
        display_version = $displayVersion
        os_architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        process_architecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        current_sid = $identity.User.Value
        process_session_id = [Diagnostics.Process]::GetCurrentProcess().SessionId
        user_interactive = [Environment]::UserInteractive
        powershell_version = $PSVersionTable.PSVersion.ToString()
    }
}

function Get-HeldFileInformation([IO.FileStream]$Stream) {
    $information = [PipeSecurityNativeMethods+ByHandleFileInformation]::new()
    if (-not [PipeSecurityNativeMethods]::GetFileInformationByHandle(
        $Stream.SafeFileHandle,
        [ref]$information
    )) {
        throw "The held runtime file identity could not be read."
    }
    $length = ([uint64]$information.FileSizeHigh * [uint64]4294967296) +
        [uint64]$information.FileSizeLow
    [pscustomobject]@{
        attributes = $information.FileAttributes
        length = $length
        file_id = ("{0:x8}:{1:x8}{2:x8}" -f
            $information.VolumeSerialNumber,
            $information.FileIndexHigh,
            $information.FileIndexLow)
    }
}

function Get-HeldStreamSha256([IO.FileStream]$Stream) {
    $Stream.Position = 0
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return [Convert]::ToHexString($algorithm.ComputeHash($Stream)).ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Get-RuntimeEvidence([string]$Path) {
    $before = Get-Item -LiteralPath $Path -Force
    if ($before.PSIsContainer -or (($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Runtime evidence requires a regular, non-reparse file."
    }
    $stream = [IO.FileStream]::new(
        $before.FullName,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        # FileShare.Read denies new/existing write and delete sharing while this
        # handle is live. Re-checking the path after opening closes the pre-open
        # reparse/replacement race; a later replacement cannot obtain delete access.
        $boundItem = Get-Item -LiteralPath $before.FullName -Force
        if ($boundItem.PSIsContainer -or
            (($boundItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Runtime path identity changed to a non-regular or reparse object."
        }
        $firstInformation = Get-HeldFileInformation $stream
        $directoryAttribute = [uint32][IO.FileAttributes]::Directory
        $reparseAttribute = [uint32][IO.FileAttributes]::ReparsePoint
        if (($firstInformation.attributes -band $directoryAttribute) -ne 0 -or
            ($firstInformation.attributes -band $reparseAttribute) -ne 0 -or
            $firstInformation.length -le 0 -or
            $firstInformation.length -gt $maximumRuntimeBytes -or
            [uint64]$stream.Length -ne $firstInformation.length) {
            throw "Held runtime identity is not an admitted bounded regular file."
        }

        $firstHash = Get-HeldStreamSha256 $stream
        $signature = Get-AuthenticodeSignature -LiteralPath $boundItem.FullName
        $secondHash = Get-HeldStreamSha256 $stream
        $secondInformation = Get-HeldFileInformation $stream
        if ($secondHash -cne $firstHash -or
            $secondInformation.file_id -cne $firstInformation.file_id -or
            $secondInformation.length -ne $firstInformation.length -or
            [uint64]$stream.Length -ne $firstInformation.length) {
            throw "Runtime identity changed while digest/signature evidence was collected."
        }

        $certificateThumbprint = if ($null -ne $signature.SignerCertificate) {
            $signature.SignerCertificate.Thumbprint.ToLowerInvariant()
        } else {
            $null
        }
        [pscustomobject]@{
            file_name = $boundItem.Name
            byte_length = $firstInformation.length
            sha256 = $firstHash
            authenticode_status = $signature.Status.ToString()
            signer_certificate_thumbprint = $certificateThumbprint
            filesystem = (Get-DriveEvidence $boundItem.FullName)
            identity_binding = "held-no-write-delete-share+windows-file-id+double-sha256"
            windows_file_id = $firstInformation.file_id
        }
    } finally {
        $stream.Dispose()
    }
}

function Get-TestCatalogue([string]$CargoPath, [string]$Package) {
    $run = Invoke-BoundedProcess -Executable $CargoPath -Arguments @(
        "test", "-p", $Package, "--lib", "--", "--list"
    ) -TimeoutSeconds $CommandTimeoutSeconds
    if ($run.TimedOut -or $run.ExitCode -ne 0) {
        throw "The $Package test catalogue could not be enumerated."
    }
    $catalogue = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($line in ($run.Stdout -split "`r?`n")) {
        if ($line -match '^(.+): test$') {
            [void]$catalogue.Add($Matches[1])
        }
    }
    if ($catalogue.Count -eq 0) {
        throw "The $Package test catalogue was empty."
    }
    return $catalogue
}

function Assert-NoDuplicateJsonKeys {
    param(
        [Parameter(Mandatory)] [Text.Json.JsonElement]$Element,
        [Parameter(Mandatory)] [string]$JsonPath
    )
    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {
                throw "duplicate JSON key at $JsonPath"
            }
            Assert-NoDuplicateJsonKeys -Element $property.Value -JsonPath ("{0}.{1}" -f $JsonPath, $property.Name)
        }
    } elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        $index = 0
        foreach ($item in $Element.EnumerateArray()) {
            Assert-NoDuplicateJsonKeys -Element $item -JsonPath ("{0}[{1}]" -f $JsonPath, $index)
            $index++
        }
    }
}

function Get-StrictJsonString {
    param(
        [Parameter(Mandatory)]$Fields,
        [Parameter(Mandatory)] [string]$Name
    )
    if (-not $Fields.ContainsKey($Name)) { throw "missing JSON field: $Name" }
    $value = $Fields[$Name]
    if ($value.ValueKind -ne [Text.Json.JsonValueKind]::String) {
        throw "JSON field must be a string: $Name"
    }
    $text = $value.GetString()
    if ($null -eq $text) { throw "JSON string field is null: $Name" }
    return $text
}

function Import-PrivilegedEvidence {
    param(
        [Parameter(Mandatory)] [string]$CaseId,
        [string]$Path,
        [string]$ExpectedEvidenceSha256,
        [string]$ExpectedHarnessSha256,
        [Parameter(Mandatory)] [string[]]$RequiredAssertions,
        [Parameter(Mandatory)] [object]$HostEvidence,
        [Parameter(Mandatory)] [object]$RuntimeEvidence
    )

    $pathSupplied = -not [string]::IsNullOrWhiteSpace($Path)
    $evidenceDigestSupplied = -not [string]::IsNullOrWhiteSpace($ExpectedEvidenceSha256)
    $harnessDigestSupplied = -not [string]::IsNullOrWhiteSpace($ExpectedHarnessSha256)
    if (-not $pathSupplied -and -not $evidenceDigestSupplied -and -not $harnessDigestSupplied) {
        $privilegedResults.Add([pscustomobject]@{
            case_id = $CaseId
            status = "NOT RUN"
            provenance = "privileged-vm-evidence-not-supplied"
            observed_at_utc = $null
            evidence_sha256 = $null
            harness_sha256 = $null
            assertions = @()
        })
        Write-Host ("[-] privileged/{0}: NOT RUN (evidence parameter absent)" -f $CaseId)
        return
    }

    if (-not $pathSupplied -or -not $evidenceDigestSupplied -or -not $harnessDigestSupplied) {
        $privilegedResults.Add([pscustomobject]@{
            case_id = $CaseId
            status = "FAIL"
            provenance = "incomplete-explicit-digest-binding"
            observed_at_utc = $null
            evidence_sha256 = $null
            harness_sha256 = $null
            assertions = @()
        })
        Write-Host ("[!] privileged/{0}: FAIL (path and both expected digests are required)" -f $CaseId)
        return
    }

    $observedEvidenceSha256 = $null
    try {
        if ($ExpectedEvidenceSha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $ExpectedHarnessSha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw "expected digests must be lower-case SHA-256"
        }
        $resolved = Resolve-RepositoryPath $Path
        $item = Get-Item -LiteralPath $resolved -Force
        if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "evidence must be a regular, non-reparse file"
        }
        $stream = [IO.FileStream]::new(
            $item.FullName,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        try {
            if ($stream.Length -le 0 -or $stream.Length -gt 1MB) {
                throw "evidence file length is outside the admitted bound"
            }
            $bytes = [byte[]]::new([int]$stream.Length)
            $offset = 0
            while ($offset -lt $bytes.Length) {
                $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
                if ($read -eq 0) { throw "evidence file was truncated during read" }
                $offset += $read
            }
            if ($stream.ReadByte() -ne -1) { throw "evidence file changed during read" }
        } finally {
            $stream.Dispose()
        }
        $observedEvidenceSha256 = [Convert]::ToHexString(
            [Security.Cryptography.SHA256]::HashData($bytes)
        ).ToLowerInvariant()
        if ($observedEvidenceSha256 -cne $ExpectedEvidenceSha256) {
            throw "evidence file digest mismatch"
        }
        $jsonText = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        $options = [Text.Json.JsonDocumentOptions]::new()
        $options.AllowTrailingCommas = $false
        $options.CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
        $options.MaxDepth = 64
        $jsonDocument = [Text.Json.JsonDocument]::Parse($jsonText, $options)
        try {
            $root = $jsonDocument.RootElement
            if ($root.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
                throw "privileged evidence root must be one JSON object"
            }
            Assert-NoDuplicateJsonKeys -Element $root -JsonPath '$'

            $requiredTopLevel = @(
                "schema_version", "case_id", "outcome", "observed_at_utc",
                "harness_sha256", "runtime_sha256", "installation_sid",
                "os_build", "filesystem", "assertions"
            )
            $allowedTopLevel = [Collections.Generic.HashSet[string]]::new(
                $requiredTopLevel,
                [StringComparer]::Ordinal
            )
            $fields = [Collections.Generic.Dictionary[string, Text.Json.JsonElement]]::new(
                [StringComparer]::Ordinal
            )
            foreach ($property in $root.EnumerateObject()) {
                if (-not $allowedTopLevel.Contains($property.Name)) {
                    throw "unknown privileged evidence field"
                }
                $fields.Add($property.Name, $property.Value)
            }
            if ($fields.Count -ne $requiredTopLevel.Count) {
                throw "privileged evidence fields are incomplete"
            }

            $schemaVersion = $fields["schema_version"]
            if ($schemaVersion.ValueKind -ne [Text.Json.JsonValueKind]::Number -or
                $schemaVersion.GetRawText() -cne "1") {
                throw "schema_version must be the JSON integer 1"
            }
            $caseValue = Get-StrictJsonString -Fields $fields -Name "case_id"
            $status = Get-StrictJsonString -Fields $fields -Name "outcome"
            $observedAtText = Get-StrictJsonString -Fields $fields -Name "observed_at_utc"
            $harnessSha256 = Get-StrictJsonString -Fields $fields -Name "harness_sha256"
            $runtimeSha256 = Get-StrictJsonString -Fields $fields -Name "runtime_sha256"
            $installationSid = Get-StrictJsonString -Fields $fields -Name "installation_sid"
            $osBuild = Get-StrictJsonString -Fields $fields -Name "os_build"
            $filesystem = Get-StrictJsonString -Fields $fields -Name "filesystem"

            if ($caseValue -cne $CaseId) { throw "case mismatch" }
            if ($status -cnotin @("PASS", "FAIL")) { throw "outcome must be PASS or FAIL" }

            $assertionsElement = $fields["assertions"]
            if ($assertionsElement.ValueKind -ne [Text.Json.JsonValueKind]::Array) {
                throw "assertions must be a JSON array"
            }
            $requiredAssertionSet = [Collections.Generic.HashSet[string]]::new(
                $RequiredAssertions,
                [StringComparer]::Ordinal
            )
            $assertionIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            $assertionCount = 0
            foreach ($assertion in $assertionsElement.EnumerateArray()) {
                $assertionCount++
                if ($assertion.ValueKind -ne [Text.Json.JsonValueKind]::Object) {
                    throw "each assertion must be one JSON object"
                }
                $assertionFields = [Collections.Generic.Dictionary[string, Text.Json.JsonElement]]::new(
                    [StringComparer]::Ordinal
                )
                foreach ($property in $assertion.EnumerateObject()) {
                    if ($property.Name -cnotin @("id", "passed")) {
                        throw "unknown assertion field"
                    }
                    $assertionFields.Add($property.Name, $property.Value)
                }
                if ($assertionFields.Count -ne 2) { throw "assertion fields are incomplete" }
                $id = Get-StrictJsonString -Fields $assertionFields -Name "id"
                if (-not $requiredAssertionSet.Contains($id) -or -not $assertionIds.Add($id)) {
                    throw "assertion ID is unknown or duplicated"
                }
                if ($assertionFields["passed"].ValueKind -ne [Text.Json.JsonValueKind]::True) {
                    throw "passed must be the JSON boolean true"
                }
            }
            if ($assertionCount -ne $RequiredAssertions.Count -or
                $assertionIds.Count -ne $RequiredAssertions.Count) {
                throw "required assertions are incomplete"
            }
        } finally {
            $jsonDocument.Dispose()
        }

        if ($runtimeSha256 -cne $RuntimeEvidence.sha256) {
            throw "runtime digest mismatch"
        }
        if ($installationSid -cne $HostEvidence.current_sid) {
            throw "installation SID mismatch"
        }
        if ($osBuild -cne $HostEvidence.os_build) {
            throw "OS build mismatch"
        }
        if ($filesystem -cne $RuntimeEvidence.filesystem.filesystem) {
            throw "filesystem mismatch"
        }
        if ($harnessSha256 -cne $ExpectedHarnessSha256) {
            throw "harness digest mismatch"
        }
        $observedAt = [DateTimeOffset]::ParseExact(
            $observedAtText,
            "O",
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
        $age = [DateTimeOffset]::UtcNow - $observedAt
        if ($age.TotalHours -lt -0.25 -or $age.TotalHours -gt $MaxPrivilegedEvidenceAgeHours) {
            throw "evidence timestamp is outside the admitted age window"
        }
        $privilegedResults.Add([pscustomobject]@{
            case_id = $CaseId
            status = $status
            provenance = "validated-imported-vm-evidence-with-explicit-digest-binding"
            observed_at_utc = $observedAt.ToUniversalTime().ToString("O")
            evidence_sha256 = $observedEvidenceSha256
            harness_sha256 = $harnessSha256
            assertions = @($RequiredAssertions)
        })
        $marker = if ($status -eq "PASS") { "+" } else { "!" }
        Write-Host ("[{0}] privileged/{1}: {2}" -f $marker, $CaseId, $status)
    } catch {
        $privilegedResults.Add([pscustomobject]@{
            case_id = $CaseId
            status = "FAIL"
            provenance = "invalid-imported-vm-evidence"
            observed_at_utc = $null
            evidence_sha256 = $observedEvidenceSha256
            harness_sha256 = $null
            assertions = @()
        })
        Write-Host ("[!] privileged/{0}: FAIL (evidence rejected)" -f $CaseId)
    }
}

$hostEvidence = $null
$repositoryFilesystem = $null
$runtimeEvidence = $null
$resolvedRuntimePath = $null
$cargoPath = $null

try {
    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    )) {
        throw "This acceptance entry requires Windows."
    }

    $hostEvidence = Get-HostEvidence
    $repositoryFilesystem = Get-DriveEvidence $repositoryRoot
    if ($repositoryFilesystem.filesystem -cne "NTFS") {
        throw "The supported acceptance filesystem is NTFS."
    }

    $cargoCommand = Get-Command cargo -CommandType Application -ErrorAction Stop
    $cargoPath = $cargoCommand.Source

    if ([string]::IsNullOrWhiteSpace($RuntimePath)) {
        $metadata = Invoke-BoundedProcess -Executable $cargoPath -Arguments @(
            "metadata", "--format-version", "1", "--no-deps"
        ) -TimeoutSeconds $CommandTimeoutSeconds
        if ($metadata.TimedOut -or $metadata.ExitCode -ne 0) {
            throw "Cargo metadata failed while locating the runtime artifact."
        }
        $targetDirectory = [string](($metadata.Stdout | ConvertFrom-Json).target_directory)
        if (-not [IO.Path]::IsPathRooted($targetDirectory)) {
            throw "Cargo returned a non-absolute target directory."
        }
        $resolvedRuntimePath = Join-Path (Join-Path $targetDirectory "debug") "mesh-daemon.exe"
        $build = Invoke-BoundedProcess -Executable $cargoPath -Arguments @(
            "build", "-p", "mesh-daemon", "--bin", "mesh-daemon"
        ) -TimeoutSeconds $CommandTimeoutSeconds
        $buildStatus = if (-not $build.TimedOut -and $build.ExitCode -eq 0) { "PASS" } else { "FAIL" }
        Add-Result -Id "runtime-build" -Status $buildStatus -EvidenceClass "local-build" `
            -Package "mesh-daemon" -ExitCode $build.ExitCode -DurationMs $build.DurationMs `
            -Assertion "The exact debug runtime used for identity evidence builds successfully."
    } else {
        $resolvedRuntimePath = Resolve-RepositoryPath $RuntimePath
    }

    if (-not (Test-Path -LiteralPath $resolvedRuntimePath -PathType Leaf)) {
        throw "The runtime artifact is absent after build or at the explicit path."
    }
    $runtimeEvidence = Get-RuntimeEvidence $resolvedRuntimePath
    $runtimeIdentityStatus = if (
        $runtimeEvidence.filesystem.filesystem -cne "NTFS" -or
        ($RequireValidSignature -and $runtimeEvidence.authenticode_status -cne "Valid")
    ) { "FAIL" } else { "PASS" }
    Add-Result -Id "runtime-identity" -Status $runtimeIdentityStatus `
        -EvidenceClass "artifact-observation" -ExitCode 0 -DurationMs 0 `
        -Assertion "Runtime SHA-256, Authenticode status, length, filesystem, and stable held-handle/file-ID binding were recorded; valid signing is required only when requested."

    $testCases = @(
        [pscustomobject]@{ Id="pipe-dacl-sqos-peer-identity"; Package="mesh-win32"; Test="pipe::tests::secure_pipe_round_trips_and_times_out"; Class="live-windows-named-pipe"; Assertion="Creates a real byte-mode pipe, verifies the protected one-SID DACL, opens with Identification/EffectiveOnly SQOS, validates both peer SID/image/digest identities, round-trips frames, and drains a timed-out overlapped read." },
        [pscustomobject]@{ Id="pipe-rejects-missing-identification-sqos"; Package="mesh-win32"; Test="pipe::tests::pipe_server_rejects_a_client_without_identification_sqos"; Class="live-windows-named-pipe"; Assertion="The server reads back TokenImpersonationLevel exactly as SecurityIdentification and rejects a real client opened without the required identification SQOS before serving frames." },
        [pscustomobject]@{ Id="peer-stable-image-digest-policy"; Package="mesh-win32"; Test="pipe::tests::production_peer_policy_accepts_only_a_verified_control_slot_artifact"; Class="windows-filesystem-security-contract"; Assertion="The peer policy admits only a protected digest-addressed stable control-slot image and rejects digest drift." },
        [pscustomobject]@{ Id="peer-wrong-digest"; Package="mesh-win32"; Test="pipe::tests::wrong_peer_digest_is_rejected"; Class="live-windows-named-pipe"; Assertion="A real pipe peer whose expected executable digest is wrong is rejected during peer authentication." },
        [pscustomobject]@{ Id="handshake-wrong-key"; Package="mesh-daemon"; Test="daemon_runtime::tests::health_is_internal_and_authentication_failure_never_reaches_router"; Class="in-process-authenticated-session"; Assertion="A client proof made with a different endpoint key never authenticates and produces zero router calls." },
        [pscustomobject]@{ Id="handshake-wrong-install"; Package="mesh-daemon"; Test="protocol_handshake::tests::rejects_wrong_id_install_version_phase_unknown_and_duplicate_field_before_proof"; Class="in-process-authenticated-session"; Assertion="Wrong install identity and other pre-proof drift fail before authentication or routing." },
        [pscustomobject]@{ Id="handshake-replay"; Package="mesh-daemon"; Test="protocol_handshake::tests::hello_nonce_replay_fails_closed"; Class="in-process-authenticated-session"; Assertion="A replayed live hello nonce returns authentication failure." },
        [pscustomobject]@{ Id="frame-split-coalesced"; Package="mesh-win32"; Test="frame::tests::accepts_split_and_coalesced_frames"; Class="framing-contract"; Assertion="Every byte chunk boundary and coalesced adjacent frames decode without boundary loss." },
        [pscustomobject]@{ Id="frame-zero-oversize"; Package="mesh-win32"; Test="frame::tests::rejects_zero_and_oversized_lengths_before_payload_read"; Class="framing-contract"; Assertion="Zero and oversized u32 lengths are rejected before payload allocation/read." },
        [pscustomobject]@{ Id="frame-utf8-boundary"; Package="mesh-win32"; Test="frame::tests::enforces_exact_request_boundary_and_utf8"; Class="framing-contract"; Assertion="The exact 1 MiB request boundary is admitted, 1 MiB plus one is rejected, and invalid UTF-8 fails." },
        [pscustomobject]@{ Id="json-duplicate-utf8-oversize"; Package="mesh-daemon"; Test="protocol_frame::tests::payload_rejects_duplicate_keys_invalid_utf8_and_bounds"; Class="strict-json-contract"; Assertion="Duplicate keys, invalid UTF-8, empty payloads, and oversized payloads fail before RPC dispatch." },
        [pscustomobject]@{ Id="slow-partial-frame-cancel"; Package="mesh-win32"; Test="pipe::tests::partial_frame_timeout_poison_closes_connection"; Class="live-windows-named-pipe"; Assertion="A slow partial header reaches its absolute deadline, CancelIoEx is drained, and the poisoned connection cannot resume." }
    )

    $catalogues = @{}
    foreach ($package in @($testCases.Package | Sort-Object -Unique)) {
        $catalogues[$package] = Get-TestCatalogue -CargoPath $cargoPath -Package $package
    }
    foreach ($case in $testCases) {
        if (-not $catalogues[$case.Package].Contains($case.Test)) {
            Add-Result -Id $case.Id -Status "FAIL" -EvidenceClass $case.Class `
                -Package $case.Package -ExactTest $case.Test `
                -Assertion ("Expected exact test is absent: " + $case.Assertion)
            continue
        }
        $run = Invoke-BoundedProcess -Executable $cargoPath -Arguments @(
            "test", "-p", $case.Package, "--lib", $case.Test, "--", "--exact", "--test-threads=1"
        ) -TimeoutSeconds $CommandTimeoutSeconds
        $status = if (-not $run.TimedOut -and $run.ExitCode -eq 0) { "PASS" } else { "FAIL" }
        Add-Result -Id $case.Id -Status $status -EvidenceClass $case.Class `
            -Package $case.Package -ExactTest $case.Test -ExitCode $run.ExitCode `
            -DurationMs $run.DurationMs -Assertion $case.Assertion
    }

    Import-PrivilegedEvidence -CaseId "cross-user" -Path $CrossUserEvidencePath `
        -ExpectedEvidenceSha256 $CrossUserExpectedEvidenceSha256 `
        -ExpectedHarnessSha256 $CrossUserExpectedHarnessSha256 `
        -RequiredAssertions @("connection_rejected", "router_calls_zero") `
        -HostEvidence $hostEvidence -RuntimeEvidence $runtimeEvidence
    Import-PrivilegedEvidence -CaseId "local-system" -Path $LocalSystemEvidencePath `
        -ExpectedEvidenceSha256 $LocalSystemExpectedEvidenceSha256 `
        -ExpectedHarnessSha256 $LocalSystemExpectedHarnessSha256 `
        -RequiredAssertions @("connection_rejected", "router_calls_zero") `
        -HostEvidence $hostEvidence -RuntimeEvidence $runtimeEvidence
    Import-PrivilegedEvidence -CaseId "remote" -Path $RemoteEvidencePath `
        -ExpectedEvidenceSha256 $RemoteExpectedEvidenceSha256 `
        -ExpectedHarnessSha256 $RemoteExpectedHarnessSha256 `
        -RequiredAssertions @("remote_connection_rejected", "router_calls_zero") `
        -HostEvidence $hostEvidence -RuntimeEvidence $runtimeEvidence
    Import-PrivilegedEvidence -CaseId "anonymous" -Path $AnonymousEvidencePath `
        -ExpectedEvidenceSha256 $AnonymousExpectedEvidenceSha256 `
        -ExpectedHarnessSha256 $AnonymousExpectedHarnessSha256 `
        -RequiredAssertions @("anonymous_connection_rejected", "router_calls_zero") `
        -HostEvidence $hostEvidence -RuntimeEvidence $runtimeEvidence
} catch {
    $fatalErrors.Add($_.Exception.Message)
    Write-Host ("[!] suite setup: FAIL ({0})" -f $_.Exception.Message)
}

$failedUnprivileged = @($results | Where-Object status -eq "FAIL").Count
$failedPrivileged = @($privilegedResults | Where-Object status -eq "FAIL").Count
$notRunPrivileged = @($privilegedResults | Where-Object status -eq "NOT RUN").Count
$overall = if (
    $fatalErrors.Count -gt 0 -or $failedUnprivileged -gt 0 -or $failedPrivileged -gt 0 -or
    ($RequirePrivilegedEvidence -and $notRunPrivileged -gt 0)
) { "FAIL" } else { "PASS" }

$finishedAt = [DateTimeOffset]::UtcNow
$report = [ordered]@{
    schema_version = 1
    suite_id = "codex-agent-mesh-pipe-security-v1"
    outcome = $overall
    started_at_utc = $startedAt.ToString("O")
    finished_at_utc = $finishedAt.ToString("O")
    duration_ms = [long]($finishedAt - $startedAt).TotalMilliseconds
    host = $hostEvidence
    repository_filesystem = $repositoryFilesystem
    runtime = $runtimeEvidence
    unprivileged_matrix = @($results)
    privileged_matrix = @($privilegedResults)
    policy = [ordered]@{
        privileged_evidence_required = [bool]$RequirePrivilegedEvidence
        valid_authenticode_required = [bool]$RequireValidSignature
        privileged_evidence_max_age_hours = $MaxPrivilegedEvidenceAgeHours
        absent_privileged_evidence_status = "NOT RUN"
        privileged_evidence_binding = "explicit-evidence-sha256+explicit-harness-sha256"
    }
    summary = [ordered]@{
        unprivileged_pass = @($results | Where-Object status -eq "PASS").Count
        unprivileged_fail = $failedUnprivileged
        privileged_pass = @($privilegedResults | Where-Object status -eq "PASS").Count
        privileged_fail = $failedPrivileged
        privileged_not_run = $notRunPrivileged
        fatal_errors = @($fatalErrors)
    }
}

if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    $stamp = $startedAt.ToString("yyyyMMddTHHmmssfffZ", [Globalization.CultureInfo]::InvariantCulture)
    $EvidencePath = Join-Path (Join-Path $repositoryRoot "target\test-evidence") ("pipe-security-{0}-{1}.json" -f $stamp, $PID)
} else {
    $EvidencePath = Resolve-RepositoryPath $EvidencePath
}
$evidenceParent = Split-Path -Parent $EvidencePath
if ([string]::IsNullOrWhiteSpace($evidenceParent)) {
    throw "The evidence path must have a parent directory."
}
[void](New-Item -ItemType Directory -Force -Path $evidenceParent)
if (Test-Path -LiteralPath $EvidencePath) {
    throw "Refusing to overwrite an existing evidence file."
}
$json = $report | ConvertTo-Json -Depth 12
$encoding = [Text.UTF8Encoding]::new($false)
$stream = [IO.FileStream]::new($EvidencePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $bytes = $encoding.GetBytes($json + "`n")
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
} finally {
    $stream.Dispose()
}

Write-Host ("Pipe security outcome: {0}" -f $overall)
Write-Host ("Evidence: {0}" -f $EvidencePath)
if ($overall -ne "PASS") { exit 1 }
