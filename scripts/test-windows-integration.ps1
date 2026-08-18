<#
.SYNOPSIS
Fail-closed Windows AC-00 clean-profile acceptance orchestrator.

.DESCRIPTION
The default invocation is a refusal/reporting path. It does not execute live
providers, create an installation, or inspect the retained LocalAppData product
root. Live/provider/privileged PASS claims are imported only from a dedicated,
marker-owned fixture evidence root and are bound to an exact command digest,
file digest, run id, and freshness window.

Use -SelfTest for deterministic contract tests. Use -RunLive only from a
dedicated clean-profile fixture after creating both owned roots and supplying
their run id. The orchestrator never deletes either supplied root.
#>
[CmdletBinding()]
param(
    [switch]$SelfTest,
    [Alias('Live')]
    [switch]$RunLive,
    [switch]$Strict,
    [string]$FixtureRoot,
    [Alias('ProviderEvidenceRoot')]
    [string]$EvidenceRoot,
    [string]$RunId,
    [string]$FixtureDriver,
    [string]$FixtureDriverSha256,
    [ValidateRange(1, 168)]
    [int]$MaxEvidenceAgeHours = 24,
    [ValidateRange(30, 1800)]
    [int]$StageTimeoutSeconds = 600,
    [string]$ReportPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:RepositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$script:OwnerMarkerName = '.ac00-owner.json'
$script:OwnerKind = 'codex-agent-mesh-ac00-owner'
$script:EvidenceKind = 'codex-agent-mesh-ac00-stage-evidence'
$script:MaximumEvidenceBytes = 16384
$script:FutureClockSkewMinutes = 5
$script:StageIds = @(
    'package-validator',
    'clean-profile-install',
    'capability-discovery',
    'delegate-claude',
    'delegate-grok',
    'delegate-kimi',
    'ordered-events-interaction',
    'bridge-restart-reconnect',
    'terminal-review-ack',
    'mcp-dashboard-parity',
    'config-export-import',
    'uninstall-retain',
    'purge-reinstall-identity',
    'privileged-windows-evidence'
)

function Get-LowerSha256Bytes {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $hasher.Dispose()
    }
}

function Get-LowerSha256Text {
    param([Parameter(Mandatory)][string]$Text)
    return Get-LowerSha256Bytes ([Text.UTF8Encoding]::new($false).GetBytes($Text))
}

function Get-LowerSha256File {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $hasher.Dispose()
        $stream.Dispose()
    }
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Text
    )
    [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
}

function Test-ExactDescendant {
    param(
        [Parameter(Mandatory)][string]$Candidate,
        [Parameter(Mandatory)][string]$Parent
    )

    $candidateFull = [IO.Path]::GetFullPath($Candidate).TrimEnd('\', '/')
    $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd('\', '/')
    if ($candidateFull.Length -le $parentFull.Length) { return $false }
    return $candidateFull.StartsWith(
        "$parentFull$([IO.Path]::DirectorySeparatorChar)",
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Test-RetainedInstallationPath {
    param([Parameter(Mandatory)][string]$Candidate)

    $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if ([string]::IsNullOrWhiteSpace($localAppData)) { return $false }
    $retainedRoot = [IO.Path]::GetFullPath((Join-Path $localAppData 'codex-agent-mesh')).TrimEnd('\', '/')
    $candidateFull = [IO.Path]::GetFullPath($Candidate).TrimEnd('\', '/')
    return $candidateFull.Equals($retainedRoot, [StringComparison]::OrdinalIgnoreCase) -or
        (Test-ExactDescendant -Candidate $candidateFull -Parent $retainedRoot)
}

function Assert-RegularPath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('Leaf', 'Container')][string]$PathType,
        [Parameter(Mandatory)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $Path -PathType $PathType)) {
        throw "$Label is absent."
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must not be a reparse point."
    }
    return $item
}

function Get-RequiredProperty {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Label
    )

    if ($Object -is [Collections.IDictionary]) {
        if (-not $Object.Contains($Name)) { throw "$Label is missing '$Name'." }
        return $Object[$Name]
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { throw "$Label is missing '$Name'." }
    return $property.Value
}

function Assert-ExactProperties {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string[]]$Allowed,
        [Parameter(Mandatory)][string[]]$Required,
        [Parameter(Mandatory)][string]$Label
    )

    $names = if ($Object -is [Collections.IDictionary]) {
        @($Object.Keys | ForEach-Object { [string]$_ })
    } else {
        @($Object.PSObject.Properties.Name)
    }
    foreach ($name in $names) {
        if ($name -cnotin $Allowed) { throw "$Label has unknown field '$name'." }
    }
    foreach ($name in $Required) {
        if ($name -cnotin $names) { throw "$Label is missing '$name'." }
    }
}

function ConvertTo-StrictTimestamp {
    param(
        [Parameter(Mandatory)][object]$Value,
        [Parameter(Mandatory)][string]$Label
    )

    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)) {
        throw "$Label must be an RFC 3339 timestamp string."
    }
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
            $Value,
            'O',
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parsed
        )) {
        throw "$Label must use the round-trip RFC 3339 format."
    }
    return $parsed
}

function Get-StageCommand {
    param(
        [Parameter(Mandatory)][ValidateSet(
            'package-validator',
            'clean-profile-install',
            'capability-discovery',
            'delegate-claude',
            'delegate-grok',
            'delegate-kimi',
            'ordered-events-interaction',
            'bridge-restart-reconnect',
            'terminal-review-ack',
            'mcp-dashboard-parity',
            'config-export-import',
            'uninstall-retain',
            'purge-reinstall-identity',
            'privileged-windows-evidence'
        )][string]$StageId,
        [string]$FixtureRootValue,
        [string]$EvidenceRootValue,
        [string]$RunIdValue,
        [string]$FixtureDriverValue,
        [string]$FixtureDriverSha256Value
    )

    $acceptanceScript = switch ($StageId) {
        'package-validator' { 'plugin-validator'; break }
        'capability-discovery' { 'scripts/test-live-adapters.ps1'; break }
        'bridge-restart-reconnect' { 'scripts/test-bridge-reconnect.ps1'; break }
        'uninstall-retain' { 'scripts/test-daemon-uninstall.ps1'; break }
        'purge-reinstall-identity' { 'scripts/test-daemon-uninstall.ps1'; break }
        'privileged-windows-evidence' { 'scripts/test-pipe-security.ps1'; break }
        default { 'owned-clean-profile-mcp-journey'; break }
    }
    return [ordered]@{
        executable = if ([string]::IsNullOrWhiteSpace($FixtureDriverValue)) { '<fixture-driver-required>' } else { $FixtureDriverValue }
        executable_sha256 = if ([string]::IsNullOrWhiteSpace($FixtureDriverSha256Value)) { $null } else { $FixtureDriverSha256Value }
        arguments = @(
            'run-stage', '--stage', $StageId,
            '--fixture-root', $FixtureRootValue,
            '--evidence-root', $EvidenceRootValue,
            '--run-id', $RunIdValue,
            '--repository-root', $script:RepositoryRoot,
            '--acceptance-script', $acceptanceScript
        )
    }
}

function ConvertTo-CommandIdentity {
    param([Parameter(Mandatory)][object]$Command)

    $identity = [ordered]@{
        executable = [string](Get-RequiredProperty -Object $Command -Name 'executable' -Label 'command')
        executable_sha256 = Get-RequiredProperty -Object $Command -Name 'executable_sha256' -Label 'command'
        arguments = @((Get-RequiredProperty -Object $Command -Name 'arguments' -Label 'command') | ForEach-Object { [string]$_ })
    }
    return $identity | ConvertTo-Json -Compress -Depth 4
}

function Get-StageCommandDigest {
    param([Parameter(Mandatory)][object]$Command)
    return Get-LowerSha256Text (ConvertTo-CommandIdentity -Command $Command)
}

function Read-OwnerMarker {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$ExpectedRunId,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][DateTimeOffset]$Now,
        [Parameter(Mandatory)][int]$MaximumAgeHours
    )

    if (Test-RetainedInstallationPath -Candidate $Root) {
        throw "$Label resolves inside the retained LocalAppData installation."
    }
    $rootItem = Assert-RegularPath -Path $Root -PathType Container -Label $Label
    $rootFull = [IO.Path]::GetFullPath($rootItem.FullName)
    $markerPath = Join-Path $rootFull $script:OwnerMarkerName
    $markerItem = Assert-RegularPath -Path $markerPath -PathType Leaf -Label "$Label owner marker"
    if (-not $markerItem.DirectoryName.Equals($rootFull.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label owner marker is not a direct child of its root."
    }
    if ($markerItem.Length -le 0 -or $markerItem.Length -gt 4096) {
        throw "$Label owner marker length is outside the admitted bound."
    }

    try { $marker = [IO.File]::ReadAllText($markerItem.FullName) | ConvertFrom-Json -DateKind String } catch {
        throw "$Label owner marker is not valid JSON."
    }
    Assert-ExactProperties -Object $marker `
        -Allowed @('schema_version', 'kind', 'run_id', 'purpose', 'created_at_utc') `
        -Required @('schema_version', 'kind', 'run_id', 'purpose', 'created_at_utc') `
        -Label "$Label owner marker"

    if ((Get-RequiredProperty $marker 'schema_version' "$Label owner marker") -ne 1 -or
        (Get-RequiredProperty $marker 'kind' "$Label owner marker") -cne $script:OwnerKind -or
        (Get-RequiredProperty $marker 'purpose' "$Label owner marker") -cne 'ac00-clean-profile' -or
        (Get-RequiredProperty $marker 'run_id' "$Label owner marker") -cne $ExpectedRunId) {
        throw "$Label owner marker identity is invalid."
    }
    if ($ExpectedRunId -cnotmatch '\A[a-z0-9][a-z0-9-]{7,63}\z') {
        throw 'RunId must be 8-64 lower-case ASCII letters, digits, or hyphens.'
    }
    $created = ConvertTo-StrictTimestamp `
        -Value (Get-RequiredProperty $marker 'created_at_utc' "$Label owner marker") `
        -Label "$Label owner marker created_at_utc"
    if ($created -gt $Now.AddMinutes($script:FutureClockSkewMinutes) -or $created -lt $Now.AddHours(-$MaximumAgeHours)) {
        throw "$Label owner marker timestamp is outside the admitted age window."
    }
    return [pscustomobject][ordered]@{
        root = $rootFull
        marker_path = $markerItem.FullName
        run_id = $ExpectedRunId
        created_at_utc = $created
    }
}

function Assert-OwnedFixtureDriver {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$ExpectedSha256,
        [Parameter(Mandatory)][string]$OwnedFixtureRoot
    )

    if ($ExpectedSha256 -cnotmatch '\A[0-9a-f]{64}\z') {
        throw 'FixtureDriverSha256 must be exactly lower-case SHA-256.'
    }
    $before = Assert-RegularPath -Path $Path -PathType Leaf -Label 'fixture driver'
    $resolved = [IO.Path]::GetFullPath($before.FullName)
    if (-not (Test-ExactDescendant -Candidate $resolved -Parent $OwnedFixtureRoot)) {
        throw 'FixtureDriver must be inside the marker-owned fixture root.'
    }
    if ([IO.Path]::GetExtension($resolved) -ne '.exe') {
        throw 'FixtureDriver must be an executable .exe fixture harness.'
    }
    $observed = Get-LowerSha256File -Path $resolved
    $after = Assert-RegularPath -Path $resolved -PathType Leaf -Label 'fixture driver'
    if ($before.Length -ne $after.Length -or
        $before.LastWriteTimeUtc.Ticks -ne $after.LastWriteTimeUtc.Ticks -or
        -not $before.FullName.Equals($after.FullName, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'FixtureDriver identity changed while its digest was collected.'
    }
    if ($observed -cne $ExpectedSha256) {
        throw 'FixtureDriverSha256 does not match the exact fixture driver bytes.'
    }
    return $resolved
}

function New-StageResult {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('PASS', 'FAIL', 'NOT RUN')][string]$Status,
        [Parameter(Mandatory)][string]$Reason,
        [Parameter(Mandatory)][object]$Command,
        [string]$EvidenceFile,
        [string]$EvidenceSha256,
        [Nullable[double]]$EvidenceAgeHours
    )

    return [pscustomobject][ordered]@{
        id = $Id
        status = $Status
        reason = if ($Reason.Length -le 512) { $Reason } else { $Reason.Substring(0, 512) }
        command = $Command
        command_sha256 = Get-StageCommandDigest -Command $Command
        evidence_file = $EvidenceFile
        evidence_sha256 = $EvidenceSha256
        evidence_age_hours = $EvidenceAgeHours
    }
}

function Assert-TrueProofField {
    param(
        [Parameter(Mandatory)][object]$Proof,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$StageId
    )
    $value = Get-RequiredProperty -Object $Proof -Name $Name -Label "$StageId proof"
    if ($value -isnot [bool] -or -not $value) {
        throw "$StageId proof field '$Name' must be true."
    }
}

function Assert-StageProof {
    param(
        [Parameter(Mandatory)][string]$StageId,
        [Parameter(Mandatory)][object]$Proof
    )

    if ($null -eq $Proof -or $Proof -isnot [pscustomobject] -or @($Proof.PSObject.Properties).Count -eq 0) {
        throw "$StageId PASS evidence requires a non-empty proof object."
    }
    if ((Get-RequiredProperty $Proof 'evidence_class' "$StageId proof") -cne 'live-windows-clean-profile-v1' -or
        (Get-RequiredProperty $Proof 'host_os' "$StageId proof") -cne 'windows' -or
        (Get-RequiredProperty $Proof 'host_arch' "$StageId proof") -cne 'x86_64') {
        throw "$StageId proof is not live Windows x64 clean-profile evidence."
    }
    foreach ($field in @('clean_profile', 'fixture_owned', 'live_process_evidence')) {
        Assert-TrueProofField -Proof $Proof -Name $field -StageId $StageId
    }

    switch ($StageId) {
        'package-validator' {
            Assert-TrueProofField $Proof 'validator_passed' $StageId
            Assert-TrueProofField $Proof 'artifact_inventory_verified' $StageId
        }
        'clean-profile-install' {
            Assert-TrueProofField $Proof 'marketplace_install' $StageId
            Assert-TrueProofField $Proof 'scheduled_daemon_setup' $StageId
        }
        'capability-discovery' {
            Assert-TrueProofField $Proof 'discovery_records_validated' $StageId
            $providers = @(Get-RequiredProperty $Proof 'providers' "$StageId proof")
            if (($providers -join '|') -cne 'claude|grok|kimi') {
                throw "$StageId proof must contain the exact Claude/Grok/Kimi provider set."
            }
        }
        { $_ -in @('delegate-claude', 'delegate-grok', 'delegate-kimi') } {
            $expectedProvider = $StageId.Substring('delegate-'.Length)
            if ((Get-RequiredProperty $Proof 'provider' "$StageId proof") -cne $expectedProvider) {
                throw "$StageId proof provider identity is invalid."
            }
            Assert-TrueProofField $Proof 'provider_process_observed' $StageId
            Assert-TrueProofField $Proof 'bounded_task_terminal' $StageId
        }
        'ordered-events-interaction' {
            Assert-TrueProofField $Proof 'ordered_events' $StageId
            Assert-TrueProofField $Proof 'interaction_round_trip' $StageId
        }
        'bridge-restart-reconnect' {
            Assert-TrueProofField $Proof 'bridge_restarted_mid_run' $StageId
            Assert-TrueProofField $Proof 'cursor_reconnected' $StageId
        }
        'terminal-review-ack' {
            if ((Get-RequiredProperty $Proof 'result_version' "$StageId proof") -ne 1) {
                throw "$StageId proof result_version must be 1."
            }
            Assert-TrueProofField $Proof 'reviewed' $StageId
            Assert-TrueProofField $Proof 'acknowledged' $StageId
        }
        'mcp-dashboard-parity' {
            Assert-TrueProofField $Proof 'same_persisted_timeline' $StageId
        }
        'config-export-import' {
            Assert-TrueProofField $Proof 'secret_free_export' $StageId
            Assert-TrueProofField $Proof 'import_validated' $StageId
        }
        'uninstall-retain' {
            Assert-TrueProofField $Proof 'task_removed' $StageId
            Assert-TrueProofField $Proof 'identity_retained' $StageId
            Assert-TrueProofField $Proof 'data_retained' $StageId
        }
        'purge-reinstall-identity' {
            Assert-TrueProofField $Proof 'explicit_purge' $StageId
            Assert-TrueProofField $Proof 'reinstalled' $StageId
            Assert-TrueProofField $Proof 'fresh_identity' $StageId
        }
        'privileged-windows-evidence' {
            Assert-TrueProofField $Proof 'privileged_fixture' $StageId
            $harnessDigest = Get-RequiredProperty $Proof 'harness_sha256' "$StageId proof"
            if ($harnessDigest -isnot [string] -or $harnessDigest -cnotmatch '\A[0-9a-f]{64}\z') {
                throw "$StageId proof requires a lower-case privileged harness SHA-256."
            }
        }
    }
}

function Read-StageEvidence {
    param(
        [Parameter(Mandatory)][string]$StageId,
        [Parameter(Mandatory)][string]$OwnedEvidenceRoot,
        [Parameter(Mandatory)][string]$ExpectedRunId,
        [Parameter(Mandatory)][object]$Command,
        [Parameter(Mandatory)][DateTimeOffset]$Now,
        [Parameter(Mandatory)][int]$MaximumAgeHours
    )

    $recordName = "$StageId.json"
    $recordPath = Join-Path $OwnedEvidenceRoot $recordName
    $digestPath = "$recordPath.sha256"
    if (-not (Test-Path -LiteralPath $recordPath) -and -not (Test-Path -LiteralPath $digestPath)) {
        return New-StageResult -Id $StageId -Status 'NOT RUN' `
            -Reason 'fresh owned stage evidence was not supplied' -Command $Command
    }

    try {
        $recordItem = Assert-RegularPath -Path $recordPath -PathType Leaf -Label "$StageId evidence"
        $digestItem = Assert-RegularPath -Path $digestPath -PathType Leaf -Label "$StageId evidence digest"
        if ($recordItem.Length -le 0 -or $recordItem.Length -gt $script:MaximumEvidenceBytes) {
            throw "$StageId evidence length is outside the admitted bound."
        }
        if ($digestItem.Length -le 0 -or $digestItem.Length -gt 128) {
            throw "$StageId evidence digest length is outside the admitted bound."
        }
        if (-not $recordItem.DirectoryName.Equals($OwnedEvidenceRoot.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase) -or
            -not $digestItem.DirectoryName.Equals($OwnedEvidenceRoot.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
            throw "$StageId evidence is not a direct child of the owned evidence root."
        }
        $expectedDigest = [IO.File]::ReadAllText($digestItem.FullName).Trim()
        if ($expectedDigest -cnotmatch '\A[0-9a-f]{64}\z') {
            throw "$StageId evidence digest must be exactly lower-case SHA-256."
        }
        $recordBytes = [IO.File]::ReadAllBytes($recordItem.FullName)
        if ($recordBytes.Length -le 0 -or $recordBytes.Length -gt $script:MaximumEvidenceBytes) {
            throw "$StageId evidence changed beyond the admitted length while it was being read."
        }
        $observedDigest = Get-LowerSha256Bytes -Bytes $recordBytes
        if ($observedDigest -cne $expectedDigest) {
            throw "$StageId evidence digest does not match the exact file bytes."
        }

        try {
            $record = ([Text.UTF8Encoding]::new($false, $true).GetString($recordBytes)) | ConvertFrom-Json -DateKind String
        } catch {
            throw "$StageId evidence is not valid JSON."
        }
        Assert-ExactProperties -Object $record `
            -Allowed @(
                'schema_version', 'kind', 'stage_id', 'status', 'run_id', 'owner_marker',
                'command_sha256', 'started_at_utc', 'completed_at_utc', 'reason', 'proof'
            ) `
            -Required @(
                'schema_version', 'kind', 'stage_id', 'status', 'run_id', 'owner_marker',
                'command_sha256', 'started_at_utc', 'completed_at_utc', 'reason', 'proof'
            ) `
            -Label "$StageId evidence"

        if ((Get-RequiredProperty $record 'schema_version' "$StageId evidence") -ne 1 -or
            (Get-RequiredProperty $record 'kind' "$StageId evidence") -cne $script:EvidenceKind -or
            (Get-RequiredProperty $record 'stage_id' "$StageId evidence") -cne $StageId -or
            (Get-RequiredProperty $record 'run_id' "$StageId evidence") -cne $ExpectedRunId -or
            (Get-RequiredProperty $record 'owner_marker' "$StageId evidence") -cne $ExpectedRunId) {
            throw "$StageId evidence identity is invalid."
        }
        $status = Get-RequiredProperty $record 'status' "$StageId evidence"
        if ($status -isnot [string] -or $status -cnotin @('PASS', 'FAIL', 'NOT RUN')) {
            throw "$StageId evidence status must be PASS, FAIL, or NOT RUN."
        }
        $commandDigest = Get-RequiredProperty $record 'command_sha256' "$StageId evidence"
        $expectedCommandDigest = Get-StageCommandDigest -Command $Command
        if ($commandDigest -isnot [string] -or $commandDigest -cne $expectedCommandDigest) {
            throw "$StageId evidence command binding is invalid."
        }
        $started = ConvertTo-StrictTimestamp `
            -Value (Get-RequiredProperty $record 'started_at_utc' "$StageId evidence") `
            -Label "$StageId evidence started_at_utc"
        $completed = ConvertTo-StrictTimestamp `
            -Value (Get-RequiredProperty $record 'completed_at_utc' "$StageId evidence") `
            -Label "$StageId evidence completed_at_utc"
        if ($completed -lt $started) { throw "$StageId evidence completed before it started." }
        if ($completed -gt $Now.AddMinutes($script:FutureClockSkewMinutes) -or $completed -lt $Now.AddHours(-$MaximumAgeHours)) {
            throw "$StageId evidence timestamp is outside the admitted age window."
        }
        $reason = Get-RequiredProperty $record 'reason' "$StageId evidence"
        if ($null -ne $reason -and $reason -isnot [string]) {
            throw "$StageId evidence reason must be null or a string."
        }
        if ($status -eq 'PASS') {
            $proof = Get-RequiredProperty $record 'proof' "$StageId evidence"
            Assert-StageProof -StageId $StageId -Proof $proof
        } elseif ([string]::IsNullOrWhiteSpace([string]$reason)) {
            throw "$StageId non-PASS evidence requires a reason."
        }

        $resultReason = if ($status -eq 'PASS') { 'validated fresh owned evidence' } else { [string]$reason }
        return New-StageResult -Id $StageId -Status $status -Reason $resultReason -Command $Command `
            -EvidenceFile $recordName -EvidenceSha256 $observedDigest `
            -EvidenceAgeHours ([Math]::Round(($Now - $completed).TotalHours, 6))
    } catch {
        return New-StageResult -Id $StageId -Status 'FAIL' -Reason $_.Exception.Message -Command $Command `
            -EvidenceFile $recordName
    }
}

function Get-OverallOutcome {
    param([Parameter(Mandatory)][object[]]$Stages)

    if (@($Stages).Count -ne $script:StageIds.Count) { return 'FAIL' }
    if (@($Stages | Where-Object status -eq 'FAIL').Count -gt 0) { return 'FAIL' }
    if (@($Stages | Where-Object status -eq 'NOT RUN').Count -gt 0) { return 'NOT RUN' }
    if (@($Stages | Where-Object status -ne 'PASS').Count -gt 0) { return 'FAIL' }
    return 'PASS'
}

function Invoke-OwnedStageCommand {
    param(
        [Parameter(Mandatory)][object]$Command,
        [Parameter(Mandatory)][int]$TimeoutSeconds,
        [Parameter(Mandatory)][ref]$Started
    )

    $Started.Value = $false
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = [string](Get-RequiredProperty $Command 'executable' 'stage command')
    foreach ($argument in @(Get-RequiredProperty $Command 'arguments' 'stage command')) {
        [void]$startInfo.ArgumentList.Add([string]$argument)
    }
    $startInfo.WorkingDirectory = $script:RepositoryRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw 'owned fixture driver did not start' }
        $Started.Value = $true
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill($true) } catch {}
            throw "owned fixture stage exceeded its $TimeoutSeconds-second deadline"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ([Text.Encoding]::UTF8.GetByteCount($stdout) -gt 65536 -or
            [Text.Encoding]::UTF8.GetByteCount($stderr) -gt 65536) {
            throw 'owned fixture stage output exceeded the 64 KiB per-stream bound'
        }
        if ($process.ExitCode -ne 0) {
            $diagnostic = if ([string]::IsNullOrWhiteSpace($stderr)) { 'no bounded stderr' } else { $stderr.Trim() }
            if ($diagnostic.Length -gt 512) { $diagnostic = $diagnostic.Substring(0, 512) }
            throw "owned fixture stage exited $($process.ExitCode): $diagnostic"
        }
    } finally {
        $process.Dispose()
    }
}

function New-TestOwnerMarker {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$TestRunId,
        [Parameter(Mandatory)][DateTimeOffset]$CreatedAt
    )
    $marker = [ordered]@{
        schema_version = 1
        kind = $script:OwnerKind
        run_id = $TestRunId
        purpose = 'ac00-clean-profile'
        created_at_utc = $CreatedAt.ToString('O')
    }
    Write-Utf8NoBom -Path (Join-Path $Root $script:OwnerMarkerName) `
        -Text ($marker | ConvertTo-Json -Compress)
}

function New-TestEvidenceRecord {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$StageId,
        [Parameter(Mandatory)][string]$TestRunId,
        [Parameter(Mandatory)][object]$Command,
        [Parameter(Mandatory)][DateTimeOffset]$CompletedAt,
        [ValidateSet('PASS', 'FAIL', 'NOT RUN')][string]$Status = 'PASS',
        [object]$Proof
    )
    if (-not $PSBoundParameters.ContainsKey('Proof') -and $Status -eq 'PASS') {
        $Proof = New-TestStageProof -StageId $StageId
    }
    $record = [ordered]@{
        schema_version = 1
        kind = $script:EvidenceKind
        stage_id = $StageId
        status = $Status
        run_id = $TestRunId
        owner_marker = $TestRunId
        command_sha256 = Get-StageCommandDigest -Command $Command
        started_at_utc = $CompletedAt.AddMinutes(-1).ToString('O')
        completed_at_utc = $CompletedAt.ToString('O')
        reason = if ($Status -eq 'PASS') { $null } else { 'deterministic-test-non-pass' }
        proof = if ($Status -eq 'PASS') { $Proof } else { $null }
    }
    $recordPath = Join-Path $Root "$StageId.json"
    Write-Utf8NoBom -Path $recordPath -Text ($record | ConvertTo-Json -Compress -Depth 5)
    Write-Utf8NoBom -Path "$recordPath.sha256" -Text (Get-LowerSha256File -Path $recordPath)
    return $recordPath
}

function New-TestStageProof {
    param([Parameter(Mandatory)][string]$StageId)

    $proof = [ordered]@{
        evidence_class = 'live-windows-clean-profile-v1'
        host_os = 'windows'
        host_arch = 'x86_64'
        clean_profile = $true
        fixture_owned = $true
        live_process_evidence = $true
    }
    switch ($StageId) {
        'package-validator' {
            $proof.validator_passed = $true
            $proof.artifact_inventory_verified = $true
        }
        'clean-profile-install' {
            $proof.marketplace_install = $true
            $proof.scheduled_daemon_setup = $true
        }
        'capability-discovery' {
            $proof.discovery_records_validated = $true
            $proof.providers = @('claude', 'grok', 'kimi')
        }
        { $_ -in @('delegate-claude', 'delegate-grok', 'delegate-kimi') } {
            $proof.provider = $StageId.Substring('delegate-'.Length)
            $proof.provider_process_observed = $true
            $proof.bounded_task_terminal = $true
        }
        'ordered-events-interaction' {
            $proof.ordered_events = $true
            $proof.interaction_round_trip = $true
        }
        'bridge-restart-reconnect' {
            $proof.bridge_restarted_mid_run = $true
            $proof.cursor_reconnected = $true
        }
        'terminal-review-ack' {
            $proof.result_version = 1
            $proof.reviewed = $true
            $proof.acknowledged = $true
        }
        'mcp-dashboard-parity' { $proof.same_persisted_timeline = $true }
        'config-export-import' {
            $proof.secret_free_export = $true
            $proof.import_validated = $true
        }
        'uninstall-retain' {
            $proof.task_removed = $true
            $proof.identity_retained = $true
            $proof.data_retained = $true
        }
        'purge-reinstall-identity' {
            $proof.explicit_purge = $true
            $proof.reinstalled = $true
            $proof.fresh_identity = $true
        }
        'privileged-windows-evidence' {
            $proof.privileged_fixture = $true
            $proof.harness_sha256 = 'a' * 64
        }
    }
    return $proof
}

function Assert-SelfTest {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )
    if (-not $Condition) { throw $Message }
}

function Invoke-SelfTests {
    $expectedStages = @(
        'package-validator', 'clean-profile-install', 'capability-discovery',
        'delegate-claude', 'delegate-grok', 'delegate-kimi',
        'ordered-events-interaction', 'bridge-restart-reconnect',
        'terminal-review-ack', 'mcp-dashboard-parity', 'config-export-import',
        'uninstall-retain', 'purge-reinstall-identity',
        'privileged-windows-evidence'
    )
    Assert-SelfTest ($script:StageIds.Count -eq $expectedStages.Count) 'stage catalogue count drifted'
    Assert-SelfTest (($script:StageIds -join '|') -ceq ($expectedStages -join '|')) 'stage catalogue order or identity drifted'
    Assert-SelfTest (@($script:StageIds | Select-Object -Unique).Count -eq $script:StageIds.Count) 'stage catalogue has duplicate ids'

    $now = [DateTimeOffset]::UtcNow
    $testRunId = 'selftest-' + [guid]::NewGuid().ToString('N')
    $testRoot = Join-Path ([IO.Path]::GetTempPath()) ("codex-agent-mesh-ac00-selftest-$([guid]::NewGuid().ToString('N'))")
    $ownedForCleanup = $false
    try {
        [void](New-Item -ItemType Directory -Path $testRoot)
        New-TestOwnerMarker -Root $testRoot -TestRunId $testRunId -CreatedAt $now
        $ownedForCleanup = $true

        $owned = Read-OwnerMarker -Root $testRoot -ExpectedRunId $testRunId -Label 'self-test root' -Now $now -MaximumAgeHours 24
        Assert-SelfTest ($owned.run_id -ceq $testRunId) 'safe owner marker was not admitted'

        $spacedFixture = Join-Path $testRoot 'fixture root with spaces'
        $spacedEvidence = Join-Path $testRoot 'evidence root with spaces'
        $testDriver = Join-Path $testRoot 'fixture driver with spaces.exe'
        $testDriverDigest = 'b' * 64
        $command = Get-StageCommand -StageId 'delegate-claude' -FixtureRootValue $spacedFixture `
            -EvidenceRootValue $spacedEvidence -RunIdValue $testRunId `
            -FixtureDriverValue $testDriver -FixtureDriverSha256Value $testDriverDigest
        Assert-SelfTest ($command.executable -ceq $testDriver) 'command executable drifted'
        Assert-SelfTest ($command.executable_sha256 -ceq $testDriverDigest) 'command executable digest drifted'
        Assert-SelfTest ($command.arguments.Count -eq 13) 'command argument count drifted'
        Assert-SelfTest ($command.arguments[2] -ceq 'delegate-claude') 'stage argument was split or reordered'
        Assert-SelfTest ($command.arguments[4] -ceq $spacedFixture) 'fixture path was split or reordered'
        Assert-SelfTest ($command.arguments[6] -ceq $spacedEvidence) 'evidence path was split or reordered'

        $missing = Read-StageEvidence -StageId 'delegate-claude' -OwnedEvidenceRoot $testRoot `
            -ExpectedRunId $testRunId -Command $command -Now $now -MaximumAgeHours 24
        Assert-SelfTest ($missing.status -ceq 'NOT RUN') 'missing evidence was not NOT RUN'

        $recordPath = New-TestEvidenceRecord -Root $testRoot -StageId 'delegate-claude' `
            -TestRunId $testRunId -Command $command -CompletedAt $now
        $valid = Read-StageEvidence -StageId 'delegate-claude' -OwnedEvidenceRoot $testRoot `
            -ExpectedRunId $testRunId -Command $command -Now $now -MaximumAgeHours 24
        Assert-SelfTest ($valid.status -ceq 'PASS') 'fresh digest-bound evidence was not admitted'

        $missingProviderProof = New-TestStageProof -StageId 'delegate-claude'
        $missingProviderProof.provider_process_observed = $false
        [void](New-TestEvidenceRecord -Root $testRoot -StageId 'delegate-claude' `
            -TestRunId $testRunId -Command $command -CompletedAt $now -Proof $missingProviderProof)
        $missingProvider = Read-StageEvidence -StageId 'delegate-claude' -OwnedEvidenceRoot $testRoot `
            -ExpectedRunId $testRunId -Command $command -Now $now -MaximumAgeHours 24
        Assert-SelfTest ($missingProvider.status -ceq 'FAIL' -and $missingProvider.reason -match 'provider_process_observed') `
            'missing provider process evidence was not rejected'

        [void](New-TestEvidenceRecord -Root $testRoot -StageId 'delegate-claude' `
            -TestRunId $testRunId -Command $command -CompletedAt $now)
        Add-Content -LiteralPath $recordPath -Value ' ' -NoNewline
        $forged = Read-StageEvidence -StageId 'delegate-claude' -OwnedEvidenceRoot $testRoot `
            -ExpectedRunId $testRunId -Command $command -Now $now -MaximumAgeHours 24
        Assert-SelfTest ($forged.status -ceq 'FAIL' -and $forged.reason -match 'digest') 'forged evidence was not rejected'

        [void](New-TestEvidenceRecord -Root $testRoot -StageId 'delegate-claude' `
            -TestRunId $testRunId -Command $command -CompletedAt $now.AddHours(-25))
        $stale = Read-StageEvidence -StageId 'delegate-claude' -OwnedEvidenceRoot $testRoot `
            -ExpectedRunId $testRunId -Command $command -Now $now -MaximumAgeHours 24
        Assert-SelfTest ($stale.status -ceq 'FAIL' -and $stale.reason -match 'age window') 'stale evidence was not rejected'

        $wrongCommand = Get-StageCommand -StageId 'delegate-grok' -FixtureRootValue $spacedFixture `
            -EvidenceRootValue $spacedEvidence -RunIdValue $testRunId `
            -FixtureDriverValue $testDriver -FixtureDriverSha256Value $testDriverDigest
        [void](New-TestEvidenceRecord -Root $testRoot -StageId 'delegate-claude' `
            -TestRunId $testRunId -Command $wrongCommand -CompletedAt $now)
        $wrongBinding = Read-StageEvidence -StageId 'delegate-claude' -OwnedEvidenceRoot $testRoot `
            -ExpectedRunId $testRunId -Command $command -Now $now -MaximumAgeHours 24
        Assert-SelfTest ($wrongBinding.status -ceq 'FAIL' -and $wrongBinding.reason -match 'command binding') 'wrong-command evidence was not rejected'

        $privilegedCommand = Get-StageCommand -StageId 'privileged-windows-evidence' `
            -FixtureRootValue $spacedFixture -EvidenceRootValue $spacedEvidence `
            -RunIdValue $testRunId -FixtureDriverValue $testDriver `
            -FixtureDriverSha256Value $testDriverDigest
        $missingPrivilegedProof = New-TestStageProof -StageId 'privileged-windows-evidence'
        $missingPrivilegedProof.privileged_fixture = $false
        [void](New-TestEvidenceRecord -Root $testRoot -StageId 'privileged-windows-evidence' `
            -TestRunId $testRunId -Command $privilegedCommand -CompletedAt $now -Proof $missingPrivilegedProof)
        $missingPrivileged = Read-StageEvidence -StageId 'privileged-windows-evidence' `
            -OwnedEvidenceRoot $testRoot -ExpectedRunId $testRunId -Command $privilegedCommand `
            -Now $now -MaximumAgeHours 24
        Assert-SelfTest ($missingPrivileged.status -ceq 'FAIL' -and $missingPrivileged.reason -match 'privileged_fixture') `
            'missing privileged evidence was not rejected'

        $passStages = @($script:StageIds | ForEach-Object { [pscustomobject]@{ status = 'PASS' } })
        Assert-SelfTest ((Get-OverallOutcome -Stages $passStages) -ceq 'PASS') 'all-pass aggregation failed'
        $passStages[3].status = 'NOT RUN'
        Assert-SelfTest ((Get-OverallOutcome -Stages $passStages) -ceq 'NOT RUN') 'not-run aggregation failed'
        $passStages[3].status = 'FAIL'
        Assert-SelfTest ((Get-OverallOutcome -Stages $passStages) -ceq 'FAIL') 'failure aggregation failed'

        $markerPath = Join-Path $testRoot $script:OwnerMarkerName
        $wrongMarker = [IO.File]::ReadAllText($markerPath).Replace($testRunId, 'selftest-00000000')
        Write-Utf8NoBom -Path $markerPath -Text $wrongMarker
        $markerRejected = $false
        try {
            [void](Read-OwnerMarker -Root $testRoot -ExpectedRunId $testRunId -Label 'self-test root' -Now $now -MaximumAgeHours 24)
        } catch { $markerRejected = $_.Exception.Message -match 'identity' }
        Assert-SelfTest $markerRejected 'wrong owner marker was not rejected'

        New-TestOwnerMarker -Root $testRoot -TestRunId $testRunId -CreatedAt $now
        $ownedDriverPath = Join-Path $testRoot 'owned-driver.exe'
        Write-Utf8NoBom -Path $ownedDriverPath -Text 'deterministic-owned-driver-v1'
        $ownedDriverDigest = Get-LowerSha256File $ownedDriverPath
        $admittedDriver = Assert-OwnedFixtureDriver -Path $ownedDriverPath `
            -ExpectedSha256 $ownedDriverDigest -OwnedFixtureRoot $testRoot
        Assert-SelfTest ($admittedDriver -ceq [IO.Path]::GetFullPath($ownedDriverPath)) 'owned driver was not admitted'
        Write-Utf8NoBom -Path $ownedDriverPath -Text 'deterministic-owned-driver-v2'
        $driverDriftRejected = $false
        try {
            [void](Assert-OwnedFixtureDriver -Path $ownedDriverPath `
                -ExpectedSha256 $ownedDriverDigest -OwnedFixtureRoot $testRoot)
        } catch { $driverDriftRejected = $_.Exception.Message -match 'does not match' }
        Assert-SelfTest $driverDriftRejected 'fixture driver digest drift was not rejected'

        $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
        if (-not [string]::IsNullOrWhiteSpace($localAppData)) {
            $retainedCandidate = Join-Path $localAppData 'codex-agent-mesh\slots\stable'
            Assert-SelfTest (Test-RetainedInstallationPath $retainedCandidate) 'retained LocalAppData path guard failed'
        }

        return [ordered]@{
            fixture = 'windows-integration-self-test-v1'
            outcome = 'PASS'
            tests = [ordered]@{
                command_construction = 'PASS'
                exact_stage_catalogue = 'PASS'
                evidence_aggregation = 'PASS'
                missing_evidence_rejection = 'PASS'
                missing_provider_evidence_rejection = 'PASS'
                missing_privileged_evidence_rejection = 'PASS'
                forged_evidence_rejection = 'PASS'
                stale_evidence_rejection = 'PASS'
                safe_path_marker_ownership = 'PASS'
                fixture_driver_digest_recheck = 'PASS'
            }
            live_adapters_run = $false
            retained_installation_touched = $false
        }
    } finally {
        if ($ownedForCleanup -and (Test-Path -LiteralPath $testRoot)) {
            $resolved = [IO.Path]::GetFullPath($testRoot)
            $temporary = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\', '/')
            $markerPath = Join-Path $resolved $script:OwnerMarkerName
            $insideTemporary = Test-ExactDescendant -Candidate $resolved -Parent $temporary
            $markerExists = Test-Path -LiteralPath $markerPath -PathType Leaf
            $reparse = @(
                Get-ChildItem -LiteralPath $resolved -Recurse -Force | Where-Object {
                    ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
                }
            )
            if (-not $insideTemporary -or -not $markerExists -or $reparse.Count -ne 0) {
                throw 'Refusing unsafe self-test cleanup.'
            }
            Remove-Item -LiteralPath $resolved -Recurse -Force
        }
    }
}

function Write-JsonReport {
    param([Parameter(Mandatory)][object]$Report)

    $json = $Report | ConvertTo-Json -Depth 8
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 131072) {
        throw 'Windows integration report exceeds the 128 KiB evidence bound.'
    }
    if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
        $parent = Split-Path -Parent ([IO.Path]::GetFullPath($ReportPath))
        if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent -PathType Container)) {
            throw 'ReportPath parent must already exist.'
        }
        if (Test-RetainedInstallationPath -Candidate $ReportPath) {
            throw 'ReportPath must not resolve inside the retained LocalAppData installation.'
        }
        if (Test-Path -LiteralPath $ReportPath) {
            throw 'Refusing to overwrite an existing report.'
        }
        Write-Utf8NoBom -Path ([IO.Path]::GetFullPath($ReportPath)) -Text $json
    }
    Write-Output $json
}

if ($SelfTest) {
    try {
        Write-JsonReport -Report (Invoke-SelfTests)
        exit 0
    } catch {
        $failure = [ordered]@{
            fixture = 'windows-integration-self-test-v1'
            outcome = 'FAIL'
            reason = $_.Exception.Message
            live_adapters_run = $false
            retained_installation_touched = $false
        }
        Write-JsonReport -Report $failure
        exit 1
    }
}

$startedAt = [DateTimeOffset]::UtcNow
$effectiveRunId = if ([string]::IsNullOrWhiteSpace($RunId)) { 'not-supplied' } else { $RunId }
$stages = [Collections.Generic.List[object]]::new()
$safetyFailures = [Collections.Generic.List[string]]::new()
$fixtureOwnership = 'NOT RUN'
$evidenceOwnership = 'NOT RUN'
$driverOwnership = 'NOT RUN'
$resolvedFixtureRoot = $null
$resolvedEvidenceRoot = $null
$resolvedFixtureDriver = $null
$liveAdapterCommandAttempted = $false
$liveAdapterCommandStarted = $false

if ($RunLive -or $Strict) {
    if ([string]::IsNullOrWhiteSpace($FixtureRoot) -or
        [string]::IsNullOrWhiteSpace($EvidenceRoot) -or
        [string]::IsNullOrWhiteSpace($RunId) -or
        [string]::IsNullOrWhiteSpace($FixtureDriver) -or
        [string]::IsNullOrWhiteSpace($FixtureDriverSha256)) {
        $safetyFailures.Add('Strict/RunLive requires FixtureRoot, EvidenceRoot, RunId, FixtureDriver, and FixtureDriverSha256 together.')
    } else {
        try {
            $ownedFixture = Read-OwnerMarker -Root $FixtureRoot -ExpectedRunId $RunId -Label 'fixture root' `
                -Now $startedAt -MaximumAgeHours $MaxEvidenceAgeHours
            $resolvedFixtureRoot = $ownedFixture.root
            $fixtureOwnership = 'PASS'
        } catch {
            $fixtureOwnership = 'FAIL'
            $safetyFailures.Add($_.Exception.Message)
        }
        try {
            $ownedEvidence = Read-OwnerMarker -Root $EvidenceRoot -ExpectedRunId $RunId -Label 'evidence root' `
                -Now $startedAt -MaximumAgeHours $MaxEvidenceAgeHours
            $resolvedEvidenceRoot = $ownedEvidence.root
            $evidenceOwnership = 'PASS'
        } catch {
            $evidenceOwnership = 'FAIL'
            $safetyFailures.Add($_.Exception.Message)
        }
        if ($fixtureOwnership -eq 'PASS' -and $evidenceOwnership -eq 'PASS') {
            if ($resolvedFixtureRoot.Equals($resolvedEvidenceRoot, [StringComparison]::OrdinalIgnoreCase)) {
                $safetyFailures.Add('FixtureRoot and EvidenceRoot must be distinct owned directories.')
            }
        }
        try {
            if ($null -eq $resolvedFixtureRoot) { throw 'Fixture root ownership is required before driver admission.' }
            $resolvedFixtureDriver = Assert-OwnedFixtureDriver -Path $FixtureDriver `
                -ExpectedSha256 $FixtureDriverSha256 -OwnedFixtureRoot $resolvedFixtureRoot
            $driverOwnership = 'PASS'
        } catch {
            $driverOwnership = 'FAIL'
            $safetyFailures.Add($_.Exception.Message)
        }
    }
}

if ($safetyFailures.Count -eq 0 -and $null -ne $resolvedFixtureDriver) {
    $FixtureRoot = $resolvedFixtureRoot
    $EvidenceRoot = $resolvedEvidenceRoot
    $FixtureDriver = $resolvedFixtureDriver
}

foreach ($stageId in $script:StageIds) {
    $command = Get-StageCommand -StageId $stageId -FixtureRootValue $FixtureRoot `
        -EvidenceRootValue $EvidenceRoot -RunIdValue $RunId `
        -FixtureDriverValue $FixtureDriver -FixtureDriverSha256Value $FixtureDriverSha256
    if (-not $RunLive -and -not $Strict) {
        $stages.Add((New-StageResult -Id $stageId -Status 'NOT RUN' `
                -Reason 'Strict/RunLive was not supplied; AC-00 live work remains opt-in' -Command $command))
    } elseif ($safetyFailures.Count -gt 0 -or $null -eq $resolvedEvidenceRoot) {
        $stages.Add((New-StageResult -Id $stageId -Status 'NOT RUN' `
                -Reason 'owned live fixture/evidence preflight did not pass' -Command $command))
    } else {
        if ($RunLive) {
            $providerStage = $stageId -in @('capability-discovery', 'delegate-claude', 'delegate-grok', 'delegate-kimi')
            if ($providerStage) { $liveAdapterCommandAttempted = $true }
            $stageStarted = $false
            try {
                [void](Assert-OwnedFixtureDriver -Path $FixtureDriver -ExpectedSha256 $FixtureDriverSha256 `
                    -OwnedFixtureRoot $resolvedFixtureRoot)
                Invoke-OwnedStageCommand -Command $command -TimeoutSeconds $StageTimeoutSeconds -Started ([ref]$stageStarted)
            } catch {
                if ($providerStage -and $stageStarted) { $liveAdapterCommandStarted = $true }
                $stages.Add((New-StageResult -Id $stageId -Status 'FAIL' `
                        -Reason $_.Exception.Message -Command $command))
                continue
            }
            if ($providerStage -and $stageStarted) { $liveAdapterCommandStarted = $true }
        }
        $stages.Add((Read-StageEvidence -StageId $stageId -OwnedEvidenceRoot $resolvedEvidenceRoot `
            -ExpectedRunId $RunId -Command $command -Now ([DateTimeOffset]::UtcNow) `
            -MaximumAgeHours $MaxEvidenceAgeHours))
    }
}

$aggregated = Get-OverallOutcome -Stages @($stages)
$overall = if ($safetyFailures.Count -gt 0 -or ($Strict -and $aggregated -ne 'PASS')) { 'FAIL' } else { $aggregated }
$report = [ordered]@{
    schema_version = 1
    fixture = 'windows-integration-ac00-v1'
    outcome = $overall
    ac = 'AC-00'
    reason = if ($overall -eq 'PASS') {
        $null
    } elseif ($safetyFailures.Count -gt 0) {
        'live fixture safety preflight failed'
    } else {
        'AC-00 is unproven until every required stage has fresh validated PASS evidence'
    }
    run_id = $effectiveRunId
    started_at_utc = $startedAt.ToString('O')
    duration_ms = [int]([DateTimeOffset]::UtcNow - $startedAt).TotalMilliseconds
    strict = [bool]$Strict
    live_opt_in = [bool]$RunLive
    live_adapter_commands_attempted = $liveAdapterCommandAttempted
    live_adapters_run = $liveAdapterCommandStarted
    retained_installation_touched = $false
    safety = [ordered]@{
        retained_localappdata_default = 'PRESERVED'
        fixture_ownership = $fixtureOwnership
        evidence_ownership = $evidenceOwnership
        driver_ownership = $driverOwnership
        failures = @($safetyFailures)
    }
    stage_catalogue = @($script:StageIds)
    stages = @($stages)
    summary = [ordered]@{
        pass = @($stages | Where-Object status -eq 'PASS').Count
        fail = @($stages | Where-Object status -eq 'FAIL').Count
        not_run = @($stages | Where-Object status -eq 'NOT RUN').Count
        required = $script:StageIds.Count
    }
    release_blockers = @(
        $stages | Where-Object status -ne 'PASS' | ForEach-Object { "$($_.id): $($_.status)" }
    )
}

Write-JsonReport -Report $report
if ($overall -eq 'PASS') { exit 0 }
if ($overall -eq 'NOT RUN') { exit 2 }
exit 1
