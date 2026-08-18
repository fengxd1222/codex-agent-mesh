[CmdletBinding()]
param(
    [ValidateRange(1, 512)] [int] $Clients = 100,
    [ValidateRange(1, 100)] [int] $Repeats = 20,
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
    "windows_control::tests::cold_start_winner_requests_task_once_and_requires_authenticated_health",
    "windows_control::tests::concurrent_start_loser_waits_without_a_second_runex",
    "windows_runtime::tests::startup_winner_rechecks_then_requests_task_exactly_once",
    "windows_runtime::tests::startup_loser_never_requests_task_and_observes_winner",
    "windows_runtime::tests::startup_deadline_reserves_handshake_and_never_exceeds_fifteen_seconds"
)

function Start-BarrierWrapper {
    param(
        [Parameter(Mandatory)] [string] $NodePath,
        [Parameter(Mandatory)] [string] $ClientScript,
        [Parameter(Mandatory)] [string] $ConfigPath,
        [Parameter(Mandatory)] [string] $ReadyPath,
        [Parameter(Mandatory)] [string] $BarrierPath,
        [Parameter(Mandatory)] [string] $ResultPath,
        [Parameter(Mandatory)] [string] $WorkingDirectory
    )

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $NodePath
    foreach ($argument in @($ClientScript, $ConfigPath, $ReadyPath, $BarrierPath, $ResultPath)) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.WorkingDirectory = $WorkingDirectory
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { $process.Dispose(); throw "Barrier wrapper could not be started." }
    return $process
}

function Assert-ClientResult {
    param(
        [Parameter(Mandatory)] [object] $Result,
        [Parameter(Mandatory)] [int] $Index,
        [Parameter(Mandatory)] [Int64] $ReleaseEpochMs,
        [Parameter(Mandatory)] [Int64] $DeadlineEpochMs
    )

    if ((Get-RequiredString $Result "protocol") -cne "codex-agent-mesh-barrier-client-v1" -or
        (Assert-Integer (Get-RequiredProperty $Result "client_index") 0 ([int]::MaxValue) "client index") -ne $Index -or
        (Get-RequiredBoolean $Result "timed_out") -or
        (Get-RequiredBoolean $Result "close_timed_out") -or
        $null -ne (Get-RequiredProperty $Result "overflow") -or
        -not (Get-RequiredBoolean $Result "protocol_valid")) {
        throw "Barrier client $Index did not return bounded valid MCP output."
    }
    $elapsed = Assert-Integer (Get-RequiredProperty $Result "elapsed_ms") 0 15000 "client elapsed time"
    $stdoutBytes = Assert-Integer (Get-RequiredProperty $Result "stdout_bytes") 1 1048576 "client stdout byte count"
    $stderrBytes = Assert-Integer (Get-RequiredProperty $Result "stderr_bytes") 0 65536 "client stderr byte count"
    $maximumLine = Assert-Integer (Get-RequiredProperty $Result "maximum_stderr_line_bytes") 0 4096 "client stderr line"
    $null = $elapsed, $stdoutBytes, $stderrBytes, $maximumLine
    if ((Assert-Integer (Get-RequiredProperty $Result "stdout_line_count") 0 100 "stdout line count") -ne 2) {
        throw "Barrier client $Index emitted unexpected stdout lines."
    }
    $outcome = Get-RequiredString $Result "tool_outcome"
    if ($outcome -cne "SUCCESS" -or (Get-RequiredString $Result "tool_result_kind") -cne "list_agents_result") {
        throw "ACTIVE singleton fixture client $Index did not return a successful list_agents_result."
    }
    $timeline = Get-RequiredProperty $Result "timeline"
    $null = Assert-Integer (Get-RequiredProperty $timeline "wrapper_ready_epoch_ms") 0 ([Int64]::MaxValue) "wrapper ready timestamp"
    $barrierObserved = Assert-Integer (Get-RequiredProperty $timeline "barrier_observed_epoch_ms") 0 ([Int64]::MaxValue) "barrier timestamp"
    $bridgeSpawned = Assert-Integer (Get-RequiredProperty $timeline "bridge_spawned_epoch_ms") 0 ([Int64]::MaxValue) "bridge spawn timestamp"
    $null = Assert-Integer (Get-RequiredProperty $timeline "request_write_started_epoch_ms") 0 ([Int64]::MaxValue) "request start timestamp"
    $null = Assert-Integer (Get-RequiredProperty $timeline "request_write_finished_epoch_ms") 0 ([Int64]::MaxValue) "request finish timestamp"
    $null = Assert-Integer (Get-RequiredProperty $timeline "first_stdout_epoch_ms") 0 ([Int64]::MaxValue) "first stdout timestamp"
    $bridgeExited = Assert-Integer (Get-RequiredProperty $timeline "bridge_exit_epoch_ms") 0 ([Int64]::MaxValue) "bridge exit timestamp"
    $bridgeClosed = Assert-Integer (Get-RequiredProperty $timeline "bridge_close_epoch_ms") 0 ([Int64]::MaxValue) "bridge close timestamp"
    $null = Assert-Integer (Get-RequiredProperty $timeline "bridge_pid") 1 ([int]::MaxValue) "bridge PID"
    if ((Assert-Integer (Get-RequiredProperty $timeline "exit_code") 0 255 "bridge exit code") -ne 0 -or
        (Assert-Integer (Get-RequiredProperty $timeline "close_code") 0 255 "bridge close code") -ne 0 -or
        $null -ne (Get-RequiredProperty $timeline "exit_signal") -or
        $null -ne (Get-RequiredProperty $timeline "close_signal")) {
        throw "Barrier client $Index did not exit cleanly after its bounded protocol outcome."
    }
    if ($barrierObserved -lt $ReleaseEpochMs -or $bridgeSpawned -lt $ReleaseEpochMs -or
        $bridgeExited -gt $DeadlineEpochMs -or $bridgeClosed -gt $DeadlineEpochMs) {
        throw "Barrier client $Index escaped the exact global 15-second window."
    }
}

function Invoke-SingletonRound {
    param(
        [Parameter(Mandatory)] [string] $Mode,
        [Parameter(Mandatory)] [int] $Repeat,
        [Parameter(Mandatory)] [object] $Preflight,
        [Parameter(Mandatory)] [string] $Driver,
        [Parameter(Mandatory)] [string] $Workspace,
        [Parameter(Mandatory)] [string] $NodePath,
        [Parameter(Mandatory)] [string] $ClientScript,
        [Parameter(Mandatory)] [string] $ArbitraryCwd
    )

    $runToken = [guid]::NewGuid().ToString("N")
    $prepare = Invoke-FixtureDriver -DriverPath $Driver -Action "singleton.prepare" -Workspace $Workspace -TimeoutSeconds 30 -Input @{
        run_token = $runToken
        mode = $Mode
        repeat = $Repeat
        clients = $Clients
        global_bound_ms = 15000
        install_id = $Preflight.install_id
        runtime_sha256 = $Preflight.runtime_sha256
        task_definition_sha256 = $Preflight.task_definition_sha256
    }
    if ((Get-RequiredString $prepare "mode") -cne $Mode -or
        (Get-RequiredString $prepare "task_state") -cnotin @("READY", "RUNNING")) {
        throw "Fixture did not establish the requested $Mode singleton precondition."
    }
    $beforeInstances = @(Get-RequiredArray $prepare "daemon_instances")
    if ($Mode -ceq "cold" -and $beforeInstances.Count -ne 0) {
        throw "Cold round began with a daemon instance still alive."
    }
    if ($Mode -ceq "warm" -and $beforeInstances.Count -ne 1) {
        throw "Warm round did not begin with exactly one authenticated daemon."
    }

    $roundRoot = Join-Path $Workspace ("round-{0}-{1:D2}" -f $Mode, $Repeat)
    [void](New-Item -ItemType Directory -Path $roundRoot)
    $barrierPath = Join-Path $roundRoot "release.json"
    $launch = Get-RequiredProperty $Preflight "bridge_launch"
    $launchFile = Get-RequiredString $launch "file"
    if (-not [IO.Path]::IsPathFullyQualified($launchFile) -or
        -not (Test-Path -LiteralPath $launchFile -PathType Leaf)) {
        throw "Fixture bridge launch file is not an exact absolute executable."
    }
    $launchArguments = @(Get-RequiredArray $launch "arguments")
    if ($launchArguments.Where({ $_ -isnot [string] }).Count -ne 0) {
        throw "Fixture bridge arguments must be an explicit string array."
    }

    $wrappers = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $Clients; $index++) {
        $configPath = Join-Path $roundRoot ("config-{0:D3}.json" -f $index)
        $readyPath = Join-Path $roundRoot ("ready-{0:D3}.json" -f $index)
        $resultPath = Join-Path $roundRoot ("result-{0:D3}.json" -f $index)
        $config = @{
            clientIndex = $index
            file = $launchFile
            arguments = $launchArguments
            cwd = $ArbitraryCwd
        } | ConvertTo-Json -Depth 10 -Compress
        [IO.File]::WriteAllText($configPath, $config, [Text.UTF8Encoding]::new($false))
        $process = Start-BarrierWrapper -NodePath $NodePath -ClientScript $ClientScript -ConfigPath $configPath -ReadyPath $readyPath -BarrierPath $barrierPath -ResultPath $resultPath -WorkingDirectory $ArbitraryCwd
        try {
            $wrapperStartTimeUtc = $process.StartTime.ToUniversalTime()
            $wrapperImagePath = [IO.Path]::GetFullPath($process.MainModule.FileName)
        } catch {
            if (-not $process.HasExited) { $process.Kill($true); [void]$process.WaitForExit(1000) }
            $process.Dispose()
            throw "Barrier wrapper identity could not be captured before use."
        }
        $wrappers.Add([pscustomobject]@{
            Index = $index
            Process = $process
            ReadyPath = $readyPath
            ResultPath = $resultPath
            StartTimeUtc = $wrapperStartTimeUtc
            ImagePath = $wrapperImagePath
        })
    }

    try {
        $readyDeadline = [Diagnostics.Stopwatch]::StartNew()
        while ($readyDeadline.ElapsedMilliseconds -lt 30000) {
            if (@($wrappers | Where-Object { -not (Test-Path -LiteralPath $_.ReadyPath -PathType Leaf) }).Count -eq 0) { break }
            Start-Sleep -Milliseconds 10
        }
        $notReady = @($wrappers | Where-Object { -not (Test-Path -LiteralPath $_.ReadyPath -PathType Leaf) })
        if ($notReady.Count -ne 0) { throw "$($notReady.Count) client wrappers did not reach the start barrier." }

        $releaseEpochMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $deadlineEpochMs = $releaseEpochMs + 15000
        $barrier = @{ release_epoch_ms = $releaseEpochMs; deadline_epoch_ms = $deadlineEpochMs } | ConvertTo-Json -Compress
        [IO.File]::WriteAllText($barrierPath, $barrier, [Text.UTF8Encoding]::new($false))
        $global = [Diagnostics.Stopwatch]::StartNew()
        while ($global.ElapsedMilliseconds -lt 15000) {
            if (@($wrappers | Where-Object { -not (Test-Path -LiteralPath $_.ResultPath -PathType Leaf) }).Count -eq 0) { break }
            Start-Sleep -Milliseconds 5
        }
        $unfinished = @($wrappers | Where-Object { -not (Test-Path -LiteralPath $_.ResultPath -PathType Leaf) })
        if ($unfinished.Count -ne 0) {
            foreach ($item in $unfinished) {
                Stop-OwnedProcessTree -RootProcess $item.Process -ExpectedStartTimeUtc $item.StartTimeUtc -ExpectedImagePath $item.ImagePath
            }
            throw "$($unfinished.Count) bridge clients exceeded the exact global 15-second bound."
        }

        $results = [Collections.Generic.List[object]]::new()
        foreach ($item in $wrappers) {
            $result = Get-Content -Raw -LiteralPath $item.ResultPath | ConvertFrom-Json -Depth 20
            Assert-ClientResult -Result $result -Index $item.Index -ReleaseEpochMs $releaseEpochMs -DeadlineEpochMs $deadlineEpochMs
            $results.Add($result)
            [void]$item.Process.WaitForExit(1000)
        }
        $bridgePids = @($results | ForEach-Object { [int]$_.timeline.bridge_pid })
        if (@($bridgePids | Sort-Object -Unique).Count -ne $Clients) {
            throw "The barrier did not produce $Clients distinct bridge PIDs."
        }

        $snapshot = Invoke-FixtureDriver -DriverPath $Driver -Action "singleton.snapshot" -Workspace $Workspace -TimeoutSeconds 30 -Input @{
            run_token = $runToken
            mode = $Mode
            repeat = $Repeat
            release_epoch_ms = $releaseEpochMs
            deadline_epoch_ms = $deadlineEpochMs
            bridge_pids = $bridgePids
        }
        $runExDelta = Assert-Integer (Get-RequiredProperty $snapshot "task_runex_delta") 0 1 "Task RunEx delta"
        $expectedRunEx = if ($Mode -ceq "cold") { 1 } else { 0 }
        if ($runExDelta -ne $expectedRunEx) { throw "$Mode round observed an invalid Task RunEx count." }
        $daemonInstances = @(Get-RequiredArray $snapshot "daemon_instances")
        if ($daemonInstances.Count -ne 1) { throw "$Mode round did not converge on exactly one daemon PID/generation." }
        $daemonPid = Assert-Integer (Get-RequiredProperty $daemonInstances[0] "pid") 1 ([int]::MaxValue) "daemon PID"
        $generation = Assert-Integer (Get-RequiredProperty $daemonInstances[0] "generation") 1 9007199254740991 "daemon generation"
        if (([IO.Path]::GetFullPath((Get-RequiredString $daemonInstances[0] "image_path"))).TrimEnd('\') -cne
            ([IO.Path]::GetFullPath($Preflight.runtime_path)).TrimEnd('\') -or
            (Get-RequiredString $daemonInstances[0] "runtime_sha256") -cne $Preflight.runtime_sha256 -or
            (Get-FileHash -LiteralPath $Preflight.runtime_path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Preflight.runtime_sha256) {
            throw "$Mode round daemon PID did not own the exact retained runtime bytes."
        }
        if ((Assert-Integer (Get-RequiredProperty $snapshot "task_running_instances") 0 100 "Task running instances") -ne 1 -or
            (Assert-Integer (Get-RequiredProperty $snapshot "daemon_lock_owner_pid") 1 ([int]::MaxValue) "daemon lock owner") -ne $daemonPid -or
            (Assert-Integer (Get-RequiredProperty $snapshot "pipe_owner_pid") 1 ([int]::MaxValue) "pipe owner") -ne $daemonPid) {
            throw "$Mode round did not bind Task, daemon lock, and pipe to one exact daemon PID."
        }
        if ((Get-RequiredString $snapshot "runtime_sha256") -cne $Preflight.runtime_sha256 -or
            (Get-RequiredString $snapshot "task_definition_sha256") -cne $Preflight.task_definition_sha256) {
            throw "$Mode round observed runtime or Scheduled Task ownership drift."
        }
        if ($Mode -ceq "warm") {
            $beforePid = Assert-Integer (Get-RequiredProperty $beforeInstances[0] "pid") 1 ([int]::MaxValue) "warm daemon PID"
            $beforeGeneration = Assert-Integer (Get-RequiredProperty $beforeInstances[0] "generation") 1 9007199254740991 "warm daemon generation"
            if ($beforePid -ne $daemonPid -or $beforeGeneration -ne $generation) {
                throw "Warm race replaced the already-ready daemon."
            }
        }
        $observations = @(Get-RequiredArray $snapshot "client_observations")
        if ($observations.Count -ne $Clients) { throw "Fixture did not observe every bridge handshake." }
        $observationPids = [Collections.Generic.List[int]]::new()
        foreach ($observation in $observations) {
            $bridgePid = Assert-Integer (Get-RequiredProperty $observation "bridge_pid") 1 ([int]::MaxValue) "observed bridge PID"
            $helperPid = Assert-Integer (Get-RequiredProperty $observation "stable_helper_pid") 1 ([int]::MaxValue) "stable helper PID"
            $connect = Assert-Integer (Get-RequiredProperty $observation "connect_started_epoch_ms") $releaseEpochMs $deadlineEpochMs "connect timestamp"
            $handshake = Assert-Integer (Get-RequiredProperty $observation "handshake_completed_epoch_ms") $connect $deadlineEpochMs "handshake timestamp"
            $null = $helperPid, $handshake
            $observationPids.Add([int]$bridgePid)
            if ($bridgePids -cnotcontains $bridgePid) { throw "Fixture reported an unknown bridge PID." }
            if ($helperPid -eq $bridgePid -or $helperPid -eq $daemonPid -or $bridgePid -eq $daemonPid -or
                ([IO.Path]::GetFullPath((Get-RequiredString $observation "stable_helper_image_path"))).TrimEnd('\') -cne
                    ([IO.Path]::GetFullPath($Preflight.runtime_path)).TrimEnd('\') -or
                (Get-RequiredString $observation "stable_helper_runtime_sha256") -cne $Preflight.runtime_sha256 -or
                (Get-RequiredString $observation "bridge_image_sha256") -cne $Preflight.bridge_sha256 -or
                ([IO.Path]::GetFullPath((Get-RequiredString $observation "bridge_image_path"))).TrimEnd('\') -cne
                    ([IO.Path]::GetFullPath($launchFile)).TrimEnd('\')) {
                throw "Fixture process identities did not match the exact bridge/helper/daemon owners."
            }
            if ((Assert-Integer (Get-RequiredProperty $observation "daemon_pid") 1 ([int]::MaxValue) "observed daemon PID") -ne $daemonPid -or
                (Assert-Integer (Get-RequiredProperty $observation "daemon_generation") 1 9007199254740991 "observed daemon generation") -ne $generation) {
                throw "A bridge authenticated to a different daemon owner."
            }
        }
        if (@($observationPids | Sort-Object -Unique).Count -ne $Clients -or
            @(Compare-Object -ReferenceObject @($bridgePids | Sort-Object) -DifferenceObject @($observationPids | Sort-Object)).Count -ne 0) {
            throw "Observed bridge PID set was not unique and exactly equal to the launched bridge PID set."
        }
        return [pscustomobject]@{
            mode = $Mode
            repeat = $Repeat
            clients = $Clients
            release_epoch_ms = $releaseEpochMs
            deadline_epoch_ms = $deadlineEpochMs
            task_runex_delta = $runExDelta
            daemon_pid = $daemonPid
            daemon_generation = $generation
        }
    } finally {
        foreach ($item in $wrappers) {
            if (-not $item.Process.HasExited) {
                Stop-OwnedProcessTree -RootProcess $item.Process -ExpectedStartTimeUtc $item.StartTimeUtc -ExpectedImagePath $item.ImagePath
            }
            $item.Process.Dispose()
        }
    }
}

$workspace = $null
$resolvedDriver = $null
$preflight = $null
$cleanupComplete = $false
try {
    $driverSpecified = -not [string]::IsNullOrWhiteSpace($FixtureDriver)
    $driverDigestSpecified = -not [string]::IsNullOrWhiteSpace($FixtureDriverSha256)
    if ($driverSpecified -ne $driverDigestSpecified) {
        throw "-FixtureDriver and -FixtureDriverSha256 must be supplied together."
    }
    if ($RequireFixture -and $SkipDeterministicEvidence) {
        throw "A strict fixture gate cannot skip deterministic singleton evidence."
    }
    if (-not $SkipDeterministicEvidence) {
        Assert-ExactCargoTestRejectsMissing -RepositoryRoot $repositoryRoot
        foreach ($test in $deterministicTests) {
            Invoke-ExactCargoTest -RepositoryRoot $repositoryRoot -TestName $test
        }
    }

    if (-not $driverSpecified) {
        Write-AcceptanceSummary @{
            suite = "daemon-singleton"
            status = "NOT_RUN"
            process_evidence = "ABSENT"
            deterministic_evidence = if ($SkipDeterministicEvidence) { "SKIPPED" } else { "PASS" }
            reason = "An explicit interactive Windows fixture driver is required for real Task RunEx, lock, pipe, and PID evidence."
            required_parameters = @("-FixtureDriver", "-FixtureDriverSha256", "-Clients 100", "-Repeats 20")
        }
        if ($RequireFixture) { exit 1 }
        exit 0
    }
    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows) -or
        [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [Runtime.InteropServices.Architecture]::X64) {
        throw "Windows x64 is required."
    }
    $resolvedDriver = Resolve-FixtureDriver -Path $FixtureDriver -ExpectedSha256 $FixtureDriverSha256
    $workspace = New-ProcessFixtureWorkspace "codex-agent-mesh-singleton-"
    $preflight = Invoke-FixtureDriver -DriverPath $resolvedDriver -Action "preflight" -Workspace $workspace -TimeoutSeconds 30 -Input @{
        suite = "daemon-singleton"
        clients = $Clients
        repeats = $Repeats
        cold_and_warm = $true
        exact_global_bound_ms = 15000
    }
    Assert-PreflightEvidence -Evidence $preflight -Capabilities @(
        "singleton_prepare_cold", "singleton_prepare_warm", "singleton_runex_counter",
        "singleton_daemon_owner", "singleton_lock_owner", "singleton_pipe_owner",
        "singleton_handshake_timestamps"
    )
    if (Get-RequiredBoolean $preflight "provider_scheduler") {
        throw "Milestone 3 singleton evidence must not claim a provider scheduler."
    }
    $nodePath = (Get-Command node -ErrorAction Stop).Source
    $clientScript = (Resolve-Path -LiteralPath (Join-Path $repositoryRoot "tests/process-fixtures/singleton-reconnect/barrier-client.mjs")).Path
    $arbitraryCwd = Join-Path $workspace "arbitrary caller cwd 空 格"
    [void](New-Item -ItemType Directory -Path $arbitraryCwd)

    $rounds = [Collections.Generic.List[object]]::new()
    for ($repeat = 1; $repeat -le $Repeats; $repeat++) {
        $rounds.Add((Invoke-SingletonRound -Mode "cold" -Repeat $repeat -Preflight $preflight -Driver $resolvedDriver -Workspace $workspace -NodePath $nodePath -ClientScript $clientScript -ArbitraryCwd $arbitraryCwd))
        $rounds.Add((Invoke-SingletonRound -Mode "warm" -Repeat $repeat -Preflight $preflight -Driver $resolvedDriver -Workspace $workspace -NodePath $nodePath -ClientScript $clientScript -ArbitraryCwd $arbitraryCwd))
    }
    $cleanupRunToken = [guid]::NewGuid().ToString("N")
    $null = Invoke-FixtureDriver -DriverPath $resolvedDriver -Action "singleton.cleanup" -Workspace $workspace -TimeoutSeconds 30 -Input @{
        run_token = $cleanupRunToken
        install_id = $preflight.install_id
        preserve_installation = $true
    }
    $cleanupComplete = $true
    Write-AcceptanceSummary @{
        suite = "daemon-singleton"
        status = "PASS"
        evidence = "INTERACTIVE_WINDOWS_PROCESS"
        clients_per_round = $Clients
        cold_repeats = $Repeats
        warm_repeats = $Repeats
        exact_global_bound_ms = 15000
        rounds = @($rounds)
        deferred = @("cross-user/LocalSystem security cases belong to test-pipe-security.ps1")
        provider_scheduler = "DEFERRED_M4"
        deterministic_evidence = if ($SkipDeterministicEvidence) { "SKIPPED" } else { "PASS" }
        fixture_driver_sha256 = $FixtureDriverSha256
    }
    exit 0
} catch {
    $failureMessage = $_.Exception.Message
    if (-not $cleanupComplete -and $null -ne $preflight -and $null -ne $workspace -and $null -ne $resolvedDriver) {
        try {
            $cleanupRunToken = [guid]::NewGuid().ToString("N")
            $null = Invoke-FixtureDriver -DriverPath $resolvedDriver -Action "singleton.cleanup" -Workspace $workspace -TimeoutSeconds 30 -Input @{
                run_token = $cleanupRunToken
                install_id = $preflight.install_id
                preserve_installation = $true
                failed_run_cleanup = $true
            }
            $cleanupComplete = $true
        } catch {
            $failureMessage = "$failureMessage Cleanup also failed: $($_.Exception.Message)"
        }
    }
    Write-AcceptanceSummary @{
        suite = "daemon-singleton"
        status = "FAIL"
        evidence = "FAIL_CLOSED"
        message = $failureMessage
    }
    exit 1
} finally {
    if ($null -ne $workspace) { Remove-ProcessFixtureWorkspace $workspace }
}
