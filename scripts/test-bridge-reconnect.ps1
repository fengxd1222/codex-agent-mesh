[CmdletBinding()]
param(
    [string] $FixtureDriver,
    [string] $FixtureDriverSha256,
    [switch] $RequireFixture,
    [switch] $SkipDeterministicEvidence
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$common = Join-Path $repositoryRoot "tests/process-fixtures/singleton-reconnect/ProcessAcceptance.Common.ps1"
. $common

$deterministicTests = @(
    "writer::tests::bounded_actor_serializes_duplicate_submissions",
    "writer::tests::committed_submit_replays_before_quota_admission_but_new_work_is_rejected",
    "router::tests::delegate_inspect_wait_and_cancel_use_only_durable_evidence",
    "storage::tests::dedup_conflict_and_terminal_tuple",
    "storage::tests::interaction_response_evidence_reopens_and_corrupt_or_legacy_rows_fail_closed",
    "storage::tests::review_semantics_are_bound_to_canonical_command_and_verified_on_reopen",
    "storage::tests::recovery_helper_process_kill_and_reopen_converges",
    "reader::tests::cursor_rejects_future_gaps_invalid_limits_and_output_overflow",
    "reader::tests::terminal_projection_rejects_broken_result_outbox_review_and_event_tuples"
)
$mutations = @("delegate_task", "send_task_input", "cancel_task", "review_task")
$killTargets = @("bridge", "stable_helper", "daemon")
$boundaries = @(
    "before_frame", "mid_header", "mid_body", "after_request_write",
    "after_persist_before_response", "mid_response", "after_response"
)

function Convert-StrictBase64 {
    param(
        [Parameter(Mandatory)] [object] $Value,
        [Parameter(Mandatory)] [string] $Label
    )

    if ($Value -isnot [string] -or $Value.Length -eq 0 -or $Value.Length -gt 1398104) {
        throw "Fixture returned an invalid $Label."
    }
    try { return [Convert]::FromBase64String($Value) } catch {
        throw "Fixture returned malformed base64 for $Label."
    }
}

function Assert-OneByteDifference {
    param(
        [Parameter(Mandatory)] [byte[]] $Original,
        [Parameter(Mandatory)] [byte[]] $Changed
    )

    if ($Original.Length -ne $Changed.Length) {
        throw "Idempotency conflict fixture changed the request length instead of one byte."
    }
    $differences = 0
    for ($index = 0; $index -lt $Original.Length; $index++) {
        if ($Original[$index] -ne $Changed[$index]) { $differences++ }
    }
    if ($differences -ne 1) {
        throw "Idempotency conflict fixture must change exactly one canonical request byte."
    }
}

function Assert-CanonicalCommandEvidence {
    param(
        [Parameter(Mandatory)] [object] $Evidence,
        [Parameter(Mandatory)] [string] $ExpectedMutation
    )

    $original = Convert-StrictBase64 (Get-RequiredString $Evidence "canonical_request_base64") "canonical request"
    $replay = Convert-StrictBase64 (Get-RequiredString $Evidence "replay_request_base64") "canonical replay"
    $conflict = Convert-StrictBase64 (Get-RequiredString $Evidence "conflict_request_base64") "canonical conflict"
    if ([Convert]::ToBase64String($original) -cne [Convert]::ToBase64String($replay)) {
        throw "Replay did not use the exact original canonical bytes."
    }
    Assert-OneByteDifference -Original $original -Changed $conflict
    try {
        $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
        $originalJson = $strictUtf8.GetString($original) | ConvertFrom-Json -Depth 30
        $conflictJson = $strictUtf8.GetString($conflict) | ConvertFrom-Json -Depth 30
    } catch {
        throw "Canonical fixture bytes are not strict UTF-8 JSON."
    }
    $commandKey = Get-RequiredString $Evidence "command_key"
    if ([string]::IsNullOrWhiteSpace($commandKey) -or
        (Get-RequiredString $originalJson "command_key") -cne $commandKey -or
        (Get-RequiredString $conflictJson "command_key") -cne $commandKey) {
        throw "Fixture did not retain one caller-supplied command key across replay/conflict."
    }
    if ((Get-RequiredString $Evidence "mutation") -cne $ExpectedMutation) {
        throw "Fixture returned evidence for the wrong mutation."
    }
    if (-not (Get-RequiredBoolean $Evidence "canonical_validated_by_rust") -or
        -not (Get-RequiredBoolean $Evidence "canonical_validated_by_typescript") -or
        -not (Get-RequiredBoolean $Evidence "responses_validated_by_rust") -or
        -not (Get-RequiredBoolean $Evidence "responses_validated_by_typescript")) {
        throw "Fixture did not cross-validate canonical commands and responses in Rust and TypeScript."
    }
    $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($original)).ToLowerInvariant()
    if ((Get-RequiredString $Evidence "canonical_request_sha256") -cne $digest) {
        throw "Fixture canonical request digest does not match its exact bytes."
    }
}

function Assert-ReconnectCase {
    param(
        [Parameter(Mandatory)] [object] $Evidence,
        [Parameter(Mandatory)] [string] $Mutation,
        [Parameter(Mandatory)] [string] $KillTarget,
        [Parameter(Mandatory)] [string] $Boundary,
        [Parameter(Mandatory)] [object] $Preflight
    )

    if ((Get-RequiredString $Evidence "kill_target") -cne $KillTarget -or
        (Get-RequiredString $Evidence "boundary") -cne $Boundary -or
        -not (Get-RequiredBoolean $Evidence "boundary_observed")) {
        throw "Fixture did not hit the requested $KillTarget/$Boundary boundary."
    }
    Assert-CanonicalCommandEvidence -Evidence $Evidence -ExpectedMutation $Mutation
    $killedPid = Assert-Integer (Get-RequiredProperty $Evidence "killed_pid") 1 ([int]::MaxValue) "killed PID"
    $processes = Get-RequiredProperty $Evidence "processes"
    $expectedPidName = switch ($KillTarget) {
        "bridge" { "bridge_pid" }
        "stable_helper" { "stable_helper_pid" }
        "daemon" { "daemon_pid" }
    }
    if ((Assert-Integer (Get-RequiredProperty $processes $expectedPidName) 1 ([int]::MaxValue) "target process PID") -ne $killedPid) {
        throw "Fixture killed a PID other than the exact requested process owner."
    }
    $imagePath = Get-RequiredString $Evidence "killed_image_path"
    $killedImageSha256 = Get-RequiredString $Evidence "killed_image_sha256"
    if (-not [IO.Path]::IsPathFullyQualified($imagePath)) {
        throw "Fixture did not record an absolute killed-process image path."
    }
    if ($KillTarget -ne "bridge") {
        if (([IO.Path]::GetFullPath($imagePath)).TrimEnd('\') -cne
            ([IO.Path]::GetFullPath($Preflight.runtime_path)).TrimEnd('\')) {
            throw "Fixture killed a helper/daemon image outside the exact retained runtime."
        }
        if ($killedImageSha256 -cne $Preflight.runtime_sha256) { throw "Killed runtime image digest drifted." }
    } elseif (([IO.Path]::GetFullPath($imagePath)).TrimEnd('\') -cne
        ([IO.Path]::GetFullPath($Preflight.bridge_launch.file)).TrimEnd('\')) {
        throw "Fixture killed a bridge image other than the exact configured bridge launcher."
    } elseif ($killedImageSha256 -cne $Preflight.bridge_sha256) {
        throw "Killed bridge image digest drifted."
    }
    $bridgePid = Assert-Integer (Get-RequiredProperty $processes "bridge_pid") 1 ([int]::MaxValue) "bridge PID"
    $helperPid = Assert-Integer (Get-RequiredProperty $processes "stable_helper_pid") 1 ([int]::MaxValue) "stable helper PID"
    $daemonPid = Assert-Integer (Get-RequiredProperty $processes "daemon_pid") 1 ([int]::MaxValue) "daemon PID"
    if (@(@($bridgePid, $helperPid, $daemonPid) | Sort-Object -Unique).Count -ne 3 -or
        ([IO.Path]::GetFullPath((Get-RequiredString $processes "bridge_image_path"))).TrimEnd('\') -cne
            ([IO.Path]::GetFullPath($Preflight.bridge_launch.file)).TrimEnd('\') -or
        ([IO.Path]::GetFullPath((Get-RequiredString $processes "stable_helper_image_path"))).TrimEnd('\') -cne
            ([IO.Path]::GetFullPath($Preflight.runtime_path)).TrimEnd('\') -or
        ([IO.Path]::GetFullPath((Get-RequiredString $processes "daemon_image_path"))).TrimEnd('\') -cne
            ([IO.Path]::GetFullPath($Preflight.runtime_path)).TrimEnd('\') -or
        (Get-RequiredString $processes "stable_helper_image_sha256") -cne $Preflight.runtime_sha256 -or
        (Get-RequiredString $processes "daemon_image_sha256") -cne $Preflight.runtime_sha256 -or
        (Get-RequiredString $processes "bridge_image_sha256") -cne $Preflight.bridge_sha256 -or
        (Get-FileHash -LiteralPath $Preflight.runtime_path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Preflight.runtime_sha256 -or
        (Get-FileHash -LiteralPath $Preflight.bridge_launch.file -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Preflight.bridge_sha256) {
        throw "Reconnect fixture did not preserve exact bridge/helper/daemon process ownership."
    }
    $effectLocator = Get-RequiredString $Evidence "effect_locator"
    if ((Assert-Integer (Get-RequiredProperty $Evidence "durable_effect_count") 0 10 "durable effect count") -ne 1 -or
        [string]::IsNullOrWhiteSpace($effectLocator)) {
        throw "Mutation replay did not converge on exactly one durable effect."
    }
    if ((Get-RequiredString $Evidence "replay_effect_locator") -cne $effectLocator -or
        (Get-RequiredString $Evidence "replay_outcome") -cne "ORIGINAL_OUTCOME" -or
        (Get-RequiredString $Evidence "conflict_code") -cne "IDEMPOTENCY_CONFLICT") {
        throw "Replay/conflict outcomes did not preserve the original durable locator."
    }
    if ((Get-RequiredBoolean $Evidence "task_cancelled") -or
        [string]::IsNullOrWhiteSpace((Get-RequiredString $Evidence "task_id"))) {
        throw "Bridge/helper/daemon death cancelled or lost the durable task."
    }
    if ((Get-RequiredBoolean $Evidence "provider_effect_claimed") -or
        (Get-RequiredString $Evidence "seed_source") -cne "test-only-deterministic-storage-router") {
        throw "M3 fixture fabricated provider-scheduler evidence."
    }
    if (-not (Get-RequiredBoolean $Evidence "cleanup_by_exact_pid") -or
        (Get-RequiredBoolean $Evidence "kill_by_name")) {
        throw "Fixture process cleanup did not use exact owned PIDs."
    }
}

function Assert-CursorResultReplay {
    param([Parameter(Mandatory)] [object] $Evidence)

    foreach ($pair in @(
        @("events_before_base64", "events_after_base64"),
        @("terminal_result_before_base64", "terminal_result_after_base64")
    )) {
        $before = Convert-StrictBase64 (Get-RequiredString $Evidence $pair[0]) $pair[0]
        $after = Convert-StrictBase64 (Get-RequiredString $Evidence $pair[1]) $pair[1]
        if ([Convert]::ToBase64String($before) -cne [Convert]::ToBase64String($after)) {
            throw "Cursor/result replay changed persisted bytes across restart."
        }
    }
    $cursor = Get-RequiredProperty $Evidence "cursor"
    $requested = Assert-Integer (Get-RequiredProperty $cursor "requested_after_seq") 0 9007199254740991 "requested cursor"
    $next = Assert-Integer (Get-RequiredProperty $cursor "next_seq") $requested 9007199254740991 "next cursor"
    $last = Assert-Integer (Get-RequiredProperty $cursor "last_committed_seq") $next 9007199254740991 "last committed cursor"
    $oldest = Assert-Integer (Get-RequiredProperty $cursor "oldest_available_seq") 1 $last "oldest cursor"
    $null = $oldest
    $daemonPidBefore = Assert-Integer (Get-RequiredProperty $Evidence "daemon_pid_before") 1 ([int]::MaxValue) "daemon PID before"
    $daemonPidAfter = Assert-Integer (Get-RequiredProperty $Evidence "daemon_pid_after") 1 ([int]::MaxValue) "daemon PID after"
    $generationBefore = Assert-Integer (Get-RequiredProperty $Evidence "daemon_generation_before") 1 9007199254740991 "daemon generation before"
    $generationAfter = Assert-Integer (Get-RequiredProperty $Evidence "daemon_generation_after") 1 9007199254740991 "daemon generation after"
    if (-not (Get-RequiredBoolean $Evidence "daemon_restarted") -or
        $daemonPidBefore -eq $daemonPidAfter -or $generationBefore -eq $generationAfter) {
        throw "Cursor/result fixture did not prove a real daemon PID/generation restart."
    }
    if ((Assert-Integer (Get-RequiredProperty $Evidence "result_version") 1 1 "result version") -ne 1 -or
        (Get-RequiredString $Evidence "seed_source") -cne "test-only-deterministic-storage-router" -or
        (Get-RequiredBoolean $Evidence "provider_effect_claimed")) {
        throw "Cursor/result replay evidence misrepresented the M3 seed boundary."
    }
    if (-not (Get-RequiredBoolean $Evidence "responses_validated_by_rust") -or
        -not (Get-RequiredBoolean $Evidence "responses_validated_by_typescript")) {
        throw "Cursor/result replay was not validated by both protocol decoders."
    }
}

$workspace = $null
$driver = $null
$preflight = $null
$cleanupComplete = $false
try {
    $driverSpecified = -not [string]::IsNullOrWhiteSpace($FixtureDriver)
    $driverDigestSpecified = -not [string]::IsNullOrWhiteSpace($FixtureDriverSha256)
    if ($driverSpecified -ne $driverDigestSpecified) {
        throw "-FixtureDriver and -FixtureDriverSha256 must be supplied together."
    }
    if ($RequireFixture -and $SkipDeterministicEvidence) {
        throw "A strict fixture gate cannot skip deterministic reconnect evidence."
    }
    if (-not $SkipDeterministicEvidence) {
        Assert-ExactCargoTestRejectsMissing -RepositoryRoot $repositoryRoot
        foreach ($test in $deterministicTests) {
            Invoke-ExactCargoTest -RepositoryRoot $repositoryRoot -TestName $test
        }
    }

    if (-not $driverSpecified) {
        Write-AcceptanceSummary @{
            suite = "bridge-reconnect"
            status = "NOT_RUN"
            process_evidence = "ABSENT"
            deterministic_storage_router_evidence = if ($SkipDeterministicEvidence) { "SKIPPED" } else { "PASS" }
            provider_scheduler = "DEFERRED_M4"
            reason = "An explicit test-only seed/kill-point fixture driver is required for bridge/helper/daemon process-boundary evidence."
            required_parameters = @("-FixtureDriver", "-FixtureDriverSha256", "-RequireFixture for a release gate")
        }
        if ($RequireFixture) { exit 1 }
        exit 0
    }

    $driver = Resolve-FixtureDriver -Path $FixtureDriver -ExpectedSha256 $FixtureDriverSha256
    $workspace = New-ProcessFixtureWorkspace "codex-agent-mesh-reconnect-"
    $preflight = Invoke-FixtureDriver -DriverPath $driver -Action "preflight" -Workspace $workspace -TimeoutSeconds 30 -Input @{
        suite = "bridge-reconnect"
        mutations = $mutations
        kill_targets = $killTargets
        boundaries = $boundaries
        provider_scheduler_required = $false
        deterministic_seed_required = $true
    }
    Assert-PreflightEvidence -Evidence $preflight -Capabilities @(
        "reconnect_bridge_kill", "reconnect_stable_helper_kill", "reconnect_daemon_kill",
        "reconnect_exact_canonical_replay", "reconnect_one_byte_conflict",
        "reconnect_durable_seed", "reconnect_cursor_result_replay"
    )
    if ((Get-RequiredBoolean $preflight "provider_scheduler") -or
        (Get-RequiredString $preflight "seed_source") -cne "test-only-deterministic-storage-router") {
        throw "Reconnect preflight must honestly identify the M3 deterministic seed boundary."
    }

    $caseResults = [Collections.Generic.List[object]]::new()
    foreach ($mutation in $mutations) {
        foreach ($killTarget in $killTargets) {
            foreach ($boundary in $boundaries) {
                $caseToken = [guid]::NewGuid().ToString("N")
                $evidence = Invoke-FixtureDriver -DriverPath $driver -Action "reconnect.case" -Workspace $workspace -TimeoutSeconds 45 -Input @{
                    case_token = $caseToken
                    mutation = $mutation
                    kill_target = $killTarget
                    boundary = $boundary
                    exact_command_key_replay = $true
                    one_byte_conflict = $true
                    install_id = $preflight.install_id
                    runtime_sha256 = $preflight.runtime_sha256
                }
                Assert-ReconnectCase -Evidence $evidence -Mutation $mutation -KillTarget $killTarget -Boundary $boundary -Preflight $preflight
                $caseResults.Add([pscustomobject]@{
                    mutation = $mutation
                    kill_target = $killTarget
                    boundary = $boundary
                    task_id = $evidence.task_id
                    effect_locator = $evidence.effect_locator
                    killed_pid = $evidence.killed_pid
                })
            }
        }
    }

    $cursorCaseToken = [guid]::NewGuid().ToString("N")
    $cursorEvidence = Invoke-FixtureDriver -DriverPath $driver -Action "reconnect.cursor-result-replay" -Workspace $workspace -TimeoutSeconds 45 -Input @{
        case_token = $cursorCaseToken
        install_id = $preflight.install_id
        include_terminal_result = $true
        include_unacknowledged_outbox = $true
        require_daemon_restart = $true
    }
    Assert-CursorResultReplay -Evidence $cursorEvidence
    $cleanupRunToken = [guid]::NewGuid().ToString("N")
    $null = Invoke-FixtureDriver -DriverPath $driver -Action "reconnect.cleanup" -Workspace $workspace -TimeoutSeconds 30 -Input @{
        run_token = $cleanupRunToken
        install_id = $preflight.install_id
        preserve_installation = $true
        delete_only_fixture_seed_rows = $true
    }
    $cleanupComplete = $true

    Write-AcceptanceSummary @{
        suite = "bridge-reconnect"
        status = "PASS"
        evidence = "INTERACTIVE_WINDOWS_PROCESS_PLUS_TEST_ONLY_DURABLE_SEED"
        cases = $caseResults.Count
        expected_cases = $mutations.Count * $killTargets.Count * $boundaries.Count
        exact_replay = "PASS"
        one_byte_conflict = "PASS"
        durable_task_survival = "PASS"
        cursor_result_replay = "PASS"
        provider_scheduler = "DEFERRED_M4"
        seed_source = "test-only-deterministic-storage-router"
        case_results = @($caseResults)
        deterministic_storage_router_evidence = if ($SkipDeterministicEvidence) { "SKIPPED" } else { "PASS" }
        fixture_driver_sha256 = $FixtureDriverSha256
    }
    exit 0
} catch {
    $failureMessage = $_.Exception.Message
    if (-not $cleanupComplete -and $null -ne $preflight -and $null -ne $workspace -and $null -ne $driver) {
        try {
            $cleanupRunToken = [guid]::NewGuid().ToString("N")
            $null = Invoke-FixtureDriver -DriverPath $driver -Action "reconnect.cleanup" -Workspace $workspace -TimeoutSeconds 30 -Input @{
                run_token = $cleanupRunToken
                install_id = $preflight.install_id
                preserve_installation = $true
                delete_only_fixture_seed_rows = $true
                failed_run_cleanup = $true
            }
            $cleanupComplete = $true
        } catch {
            $failureMessage = "$failureMessage Cleanup also failed: $($_.Exception.Message)"
        }
    }
    Write-AcceptanceSummary @{
        suite = "bridge-reconnect"
        status = "FAIL"
        evidence = "FAIL_CLOSED"
        provider_scheduler = "DEFERRED_M4"
        message = $failureMessage
    }
    exit 1
} finally {
    if ($null -ne $workspace) { Remove-ProcessFixtureWorkspace $workspace }
}
