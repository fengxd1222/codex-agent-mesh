param(
    [string]$RuntimePath,
    [switch]$SkipBuild,
    [switch]$Strict,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$fixtureRoot = Join-Path $repositoryRoot 'tests\process-fixtures\scheduled-job'
. (Join-Path $fixtureRoot 'LiveFixture.Common.ps1')

function ConvertTo-WindowsCommandLineArgument {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') { return $Value }
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (2 * $slashes + 1)))
            [void]$builder.Append('"')
        } else {
            if ($slashes) { [void]$builder.Append(('\' * $slashes)) }
            [void]$builder.Append($character)
        }
        $slashes = 0
    }
    if ($slashes) { [void]$builder.Append(('\' * (2 * $slashes))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function New-JobChild {
    param(
        [Parameter(Mandatory)][ValidateSet('start','wait')][string]$Mode,
        [Parameter(Mandatory)][string]$Runtime,
        [Parameter(Mandatory)][string]$Cwd,
        [Parameter(Mandatory)][string]$ReadyPath,
        [Parameter(Mandatory)][string]$BreakawayPath,
        [string]$CompletionPath,
        [string]$TaskId,
        [long]$AfterSeq = 0
    )
    $pwsh = (Get-Process -Id $PID).Path
    $arguments = @($pwsh,'-NoProfile','-File',(Join-Path $fixtureRoot 'job-child.ps1'),'-Mode',$Mode,'-RuntimePath',$Runtime,'-WorkingDirectory',$Cwd,'-ReadyPath',$ReadyPath,'-BreakawayPath',$BreakawayPath)
    if ($CompletionPath) { $arguments += @('-CompletionPath',$CompletionPath) }
    if ($TaskId) { $arguments += @('-TaskId',$TaskId,'-AfterSeq',[string]$AfterSeq) }
    $commandLine = ($arguments | ForEach-Object { ConvertTo-WindowsCommandLineArgument -Value ([string]$_) }) -join ' '
    return [MeshKillOnCloseJob]::Launch($pwsh,$commandLine,$Cwd)
}

function Wait-FixtureFile {
    param([Parameter(Mandatory)][string]$Path,[int]$TimeoutMs = 5000)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $Path -PathType Leaf) { return [IO.File]::ReadAllText($Path) }
        Start-Sleep -Milliseconds 10
    }
    throw "fixture marker timed out: $([IO.Path]::GetFileName($Path))"
}

function Wait-TaskInstance {
    param([Parameter(Mandatory)][string]$TaskPath,[string]$CompletionPath,[int]$TimeoutMs = 15000)
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    while ([DateTime]::UtcNow -lt $deadline) {
        $task = Get-MeshTaskEvidence -TaskPath $TaskPath
        if ($task -and $task.running_instance_pids.Count -gt 0) { return $task }
        if ($CompletionPath -and (Test-Path -LiteralPath $CompletionPath -PathType Leaf)) {
            $completion = [IO.File]::ReadAllText($CompletionPath) | ConvertFrom-Json
            throw "start helper exited before a running task instance was observed (exit $($completion.exit_code), stdout bytes $($completion.stdout_bytes), stderr bytes $($completion.stderr_bytes), bounded diagnostic truncated $($completion.stderr_truncated))"
        }
        Start-Sleep -Milliseconds 5
    }
    throw 'scheduled daemon did not expose a running task instance in time'
}

function Get-MeshOptionalPropertyValue {
    param($InputObject,[Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function ConvertTo-MeshBoundedObservationText {
    param($Value,[Parameter(Mandatory)][string]$Field,[int]$MaximumUtf8Bytes = 256,[switch]$Digest)
    if ($null -eq $Value) { return $null }
    $text = [string]$Value
    if ($Digest -and $text -notmatch '\A[0-9a-f]{64}\z') { throw "health observation $Field is not an exact digest" }
    if ([Text.Encoding]::UTF8.GetByteCount($text) -gt $MaximumUtf8Bytes) { throw "health observation $Field exceeds its evidence bound" }
    return $text
}

function ConvertTo-MeshHealthControlBody {
    param([Parameter(Mandatory)]$Body)
    $record = Get-MeshOptionalPropertyValue $Body 'record'
    $health = if ($record) { Get-MeshOptionalPropertyValue $record 'health' } else { Get-MeshOptionalPropertyValue $Body 'health' }
    $task = if ($record) { Get-MeshOptionalPropertyValue $record 'task' } else { $null }
    $error = Get-MeshOptionalPropertyValue $Body 'error'
    $ok = Get-MeshOptionalPropertyValue $Body 'ok'
    [pscustomobject][ordered]@{
        kind = ConvertTo-MeshBoundedObservationText (Get-MeshOptionalPropertyValue $Body 'kind') kind 64
        operation = ConvertTo-MeshBoundedObservationText (Get-MeshOptionalPropertyValue $Body 'operation') operation 32
        ok = if ($null -eq $ok) { $null } else { [bool]$ok }
        lifecycle = ConvertTo-MeshBoundedObservationText (Get-MeshOptionalPropertyValue $Body 'lifecycle') lifecycle 32
        error_code = ConvertTo-MeshBoundedObservationText (Get-MeshOptionalPropertyValue $error 'code') error_code 64
        record_present = [bool]$record
        health = if ($health) {
            [pscustomobject][ordered]@{
                authenticated = [bool](Get-MeshOptionalPropertyValue $health 'authenticated')
                daemon_generation = Get-MeshOptionalPropertyValue $health 'daemon_generation'
                daemon_state = ConvertTo-MeshBoundedObservationText (Get-MeshOptionalPropertyValue $health 'daemon_state') daemon_state 32
                diagnostic = ConvertTo-MeshBoundedObservationText (Get-MeshOptionalPropertyValue $health 'diagnostic') diagnostic 128
            }
        } else { $null }
        task = if ($task) {
            [pscustomobject][ordered]@{
                state = ConvertTo-MeshBoundedObservationText (Get-MeshOptionalPropertyValue $task 'state') task_state 32
                last_task_result = Get-MeshOptionalPropertyValue $task 'last_task_result'
                running_instances = Get-MeshOptionalPropertyValue $task 'running_instances'
                expected_definition_sha256 = ConvertTo-MeshBoundedObservationText (Get-MeshOptionalPropertyValue $task 'expected_definition_sha256') expected_definition_sha256 64 -Digest
                actual_definition_sha256 = ConvertTo-MeshBoundedObservationText (Get-MeshOptionalPropertyValue $task 'actual_definition_sha256') actual_definition_sha256 64 -Digest
            }
        } else { $null }
        runtime = if ($record) {
            [pscustomobject][ordered]@{
                integrity = ConvertTo-MeshBoundedObservationText (Get-MeshOptionalPropertyValue $record 'runtime_integrity') runtime_integrity 32
                expected_sha256 = ConvertTo-MeshBoundedObservationText (Get-MeshOptionalPropertyValue $record 'runtime_expected_sha256') runtime_expected_sha256 64 -Digest
                actual_sha256 = ConvertTo-MeshBoundedObservationText (Get-MeshOptionalPropertyValue $record 'runtime_actual_sha256') runtime_actual_sha256 64 -Digest
            }
        } else { $null }
    }
}

function Get-MeshScheduledDaemonProcessEvidence {
    param(
        [Parameter(Mandatory)][int]$ProcessId,
        [Parameter(Mandatory)][string]$ExpectedImagePath,
        [Parameter(Mandatory)][string]$ExpectedImageSha256,
        [Parameter(Mandatory)][hashtable]$Cache
    )
    try {
        $process = [Diagnostics.Process]::GetProcessById($ProcessId)
        try {
            $creation = $process.StartTime.ToUniversalTime()
            $imagePath = [IO.Path]::GetFullPath($process.MainModule.FileName)
            $process.Refresh()
            if ($process.HasExited -or $process.StartTime.ToUniversalTime().Ticks -ne $creation.Ticks) { throw 'identity changed' }
        } finally { $process.Dispose() }
        if (-not $imagePath.Equals([IO.Path]::GetFullPath($ExpectedImagePath),[StringComparison]::OrdinalIgnoreCase)) { throw 'image changed' }
        $cacheKey = "$ProcessId|$($creation.Ticks)"
        if ($Cache.ContainsKey($cacheKey)) { return $Cache[$cacheKey] }
        $runtime = Get-MeshRuntimeEvidence -Path $imagePath
        if ($runtime.sha256 -cne $ExpectedImageSha256) { throw 'digest changed' }
        $evidence = [pscustomobject][ordered]@{
            pid = $ProcessId
            creation_time_utc = $creation.ToString('O')
            image_path = $imagePath
            image_sha256 = $runtime.sha256
            image_byte_length = $runtime.byte_length
            signature_status = $runtime.signature_status
            signer_certificate_sha256 = $runtime.signer_certificate_sha256
        }
        $Cache[$cacheKey] = $evidence
        return $evidence
    } catch {
        throw 'scheduled daemon process identity observation is ambiguous'
    }
}

function Wait-AuthenticatedDaemonStatus {
    param(
        [Parameter(Mandatory)][string]$Runtime,
        [Parameter(Mandatory)][string]$Cwd,
        [Parameter(Mandatory)][string]$TaskPath,
        [Parameter(Mandatory)][object[]]$ExpectedProcesses,
        [Parameter(Mandatory)][string]$ExpectedImagePath,
        [Parameter(Mandatory)][string]$ExpectedImageSha256,
        [Parameter(Mandatory)][string]$ExpectedTaskXmlSha256,
        [Parameter(Mandatory)][string]$ExpectedDefinitionSha256,
        [Parameter(Mandatory)][ref]$Timeline,
        [Parameter(Mandatory)][ref]$PollElapsedMs,
        [ValidateRange(1,60000)][int]$TimeoutMs = 15000,
        [ValidateRange(1,64)][int]$MaximumObservations = 32,
        [ValidateRange(1024,262144)][int]$MaximumTimelineBytes = 131072,
        [scriptblock]$StatusProbe,
        [scriptblock]$TaskProbe,
        [scriptblock]$IdentityProbe,
        [scriptblock]$MonotonicMilliseconds,
        [scriptblock]$DelayAction
    )
    $identityCache = @{}
    if (-not $StatusProbe) { $StatusProbe = { param($remaining) Invoke-MeshControl -RuntimePath $Runtime -Operation status -WorkingDirectory $Cwd -TimeoutMs $remaining }.GetNewClosure() }
    if (-not $TaskProbe) { $TaskProbe = { Get-MeshTaskEvidence -TaskPath $TaskPath }.GetNewClosure() }
    if (-not $IdentityProbe) { $IdentityProbe = { param($pid) Get-MeshScheduledDaemonProcessEvidence -ProcessId $pid -ExpectedImagePath $ExpectedImagePath -ExpectedImageSha256 $ExpectedImageSha256 -Cache $identityCache }.GetNewClosure() }
    $clock = $null
    if (-not $MonotonicMilliseconds) {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $MonotonicMilliseconds = { [long]$clock.ElapsedMilliseconds }.GetNewClosure()
    }
    if (-not $DelayAction) { $DelayAction = { param($milliseconds) Start-Sleep -Milliseconds $milliseconds } }

    foreach ($digestValue in @($ExpectedImageSha256,$ExpectedTaskXmlSha256,$ExpectedDefinitionSha256)) {
        if ($digestValue -notmatch '\A[0-9a-f]{64}\z') { throw 'scheduled daemon expected digest evidence is invalid' }
    }
    $expectedByPid = @{}
    foreach ($expected in $ExpectedProcesses) {
        $expectedPid = [int](Get-MeshOptionalPropertyValue $expected 'pid')
        $expectedCreation = ConvertTo-MeshBoundedObservationText (Get-MeshOptionalPropertyValue $expected 'creation_time_utc') creation_time_utc 64
        if ($expectedPid -le 0 -or $expectedByPid.ContainsKey($expectedPid)) { throw 'scheduled daemon expected process identity is ambiguous' }
        if (-not $expectedCreation) { throw 'scheduled daemon expected process creation time is missing' }
        if ([string](Get-MeshOptionalPropertyValue $expected 'image_sha256') -cne $ExpectedImageSha256 -or
            -not ([string](Get-MeshOptionalPropertyValue $expected 'image_path')).Equals([IO.Path]::GetFullPath($ExpectedImagePath),[StringComparison]::OrdinalIgnoreCase)) {
            throw 'scheduled daemon expected process identity drifted'
        }
        $expectedByPid[$expectedPid] = $expected
    }
    if ($expectedByPid.Count -eq 0) { throw 'scheduled daemon expected process identity is missing' }

    $observations = [Collections.Generic.List[object]]::new()
    $timelineBytes = 2
    $lastElapsed = -1L
    $attempt = 0
    try {
        for (;;) {
            $beforeProbe = [long](& $MonotonicMilliseconds)
            if ($beforeProbe -lt $lastElapsed) { throw 'health poll monotonic clock regressed' }
            if ($beforeProbe -ge $TimeoutMs) { throw 'scheduled daemon did not publish authenticated health after fixture job close' }
            if ($observations.Count -ge $MaximumObservations) { throw 'health observation timeline exceeds its count bound' }
            $remaining = [int][Math]::Max(1,$TimeoutMs-$beforeProbe)
            $status = & $StatusProbe $remaining
            $task = & $TaskProbe
            $elapsed = [long](& $MonotonicMilliseconds)
            if ($elapsed -lt $beforeProbe) { throw 'health poll monotonic clock regressed' }
            $lastElapsed = $elapsed
            $controlBody = ConvertTo-MeshHealthControlBody -Body $status.body
            $controlCode = $controlBody.error_code
            $ambiguity = $null
            $processes = @()
            $taskSummary = if ($task) {
                $pids = @($task.running_instance_pids | ForEach-Object { [int]$_ })
                if (@($pids | Select-Object -Unique).Count -ne $pids.Count) { $ambiguity = 'DUPLICATE_TASK_PID' }
                if ([string]$task.xml_sha256 -cne $ExpectedTaskXmlSha256) { $ambiguity = 'TASK_DEFINITION_XML_DRIFT' }
                foreach ($daemonPid in $pids) {
                    if (-not $expectedByPid.ContainsKey($daemonPid)) { $ambiguity = 'UNEXPECTED_TASK_PID'; continue }
                    try { $identity = & $IdentityProbe $daemonPid } catch { $ambiguity = 'PROCESS_IDENTITY_UNAVAILABLE'; continue }
                    $expected = $expectedByPid[$daemonPid]
                    if ([string]$identity.creation_time_utc -cne [string]$expected.creation_time_utc -or
                        [string]$identity.image_sha256 -cne $ExpectedImageSha256 -or
                        -not ([string]$identity.image_path).Equals([IO.Path]::GetFullPath($ExpectedImagePath),[StringComparison]::OrdinalIgnoreCase)) {
                        $ambiguity = 'PROCESS_IDENTITY_DRIFT'
                    }
                    $processes += $identity
                }
                [pscustomobject][ordered]@{
                    state = [string]$task.state
                    last_task_result = [int]$task.last_task_result
                    running_instance_pids = $pids
                    xml_sha256 = [string]$task.xml_sha256
                }
            } else {
                [pscustomobject][ordered]@{ state='ABSENT'; last_task_result=$null; running_instance_pids=@(); xml_sha256=$null }
            }

            if ($status.exit_code -eq 0) {
                if (-not $controlBody.record_present -or -not $controlBody.task) { $ambiguity = 'CONTROL_RECORD_OR_TASK_MISSING' }
                elseif ($controlBody.task.expected_definition_sha256 -cne $ExpectedDefinitionSha256 -or $controlBody.task.actual_definition_sha256 -cne $ExpectedDefinitionSha256) { $ambiguity = 'CONTROL_DEFINITION_DRIFT' }
                elseif ([string]$controlBody.task.state -cne [string]$taskSummary.state -or [int]$controlBody.task.running_instances -ne @($taskSummary.running_instance_pids).Count) { $ambiguity = 'CONTROL_TASK_OBSERVATION_RACE' }
                elseif ($null -ne $controlBody.task.last_task_result -and $null -ne $taskSummary.last_task_result -and [int]$controlBody.task.last_task_result -ne [int]$taskSummary.last_task_result) { $ambiguity = 'CONTROL_TASK_RESULT_RACE' }
            }

            $observation = [pscustomobject][ordered]@{
                index = $observations.Count
                probe_started_elapsed_ms = $beforeProbe
                probe_completed_elapsed_ms = $elapsed
                probe_duration_ms = $elapsed-$beforeProbe
                monotonic_elapsed_ms = $elapsed
                control_exit_code = [int]$status.exit_code
                control_code = $controlCode
                control_body = $controlBody
                control_stderr_bytes = [long]$status.stderr_bytes
                control_stderr_sha256 = Get-MeshOptionalPropertyValue $status 'stderr_sha256'
                task = $taskSummary
                processes = $processes
                identity_ambiguity = $ambiguity
            }
            $encodedBytes = [Text.Encoding]::UTF8.GetByteCount(($observation | ConvertTo-Json -Compress -Depth 16)) + 1
            if ($timelineBytes + $encodedBytes -gt $MaximumTimelineBytes) { throw 'health observation timeline exceeds its byte bound' }
            $timelineBytes += $encodedBytes
            $observations.Add($observation)
            if ($ambiguity) { throw "scheduled daemon identity observation is ambiguous ($ambiguity)" }

            if ($status.exit_code -eq 0 -and $controlBody.health -and $controlBody.health.authenticated) {
                if ($processes.Count -eq 0) { throw 'authenticated health had no exact scheduled daemon process identity' }
                return $status
            }
            if ($elapsed -ge $TimeoutMs) { throw 'scheduled daemon did not publish authenticated health after fixture job close' }
            $backoff = if ($attempt -eq 0) { 250 } else { 500 }
            $remainingAfterProbe = $TimeoutMs-$elapsed
            $delay = [int][Math]::Min($backoff,$remainingAfterProbe)
            if ($delay -gt 0) { & $DelayAction $delay }
            $attempt++
        }
    } finally {
        $Timeline.Value = @($observations)
        $PollElapsedMs.Value = [long](& $MonotonicMilliseconds)
        if ($clock) { $clock.Stop() }
    }
}

function Get-FixtureJobProcessEvidence {
    param([Parameter(Mandatory)][MeshKillOnCloseJob]$Job)
    $rows = @()
    $directDaemon = $false
    foreach ($processId in $Job.ActiveProcessIds()) {
        try { $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $processId" -ErrorAction Stop }
        catch { throw [UnauthorizedAccessException]::new('fixture process command line privilege is unavailable',$_.Exception) }
        if (-not $process -or -not $process.CommandLine) { throw [UnauthorizedAccessException]::new('fixture process command line privilege is unavailable') }
        $arguments = [MeshFixtureNative]::ParseCommandLine([string]$process.CommandLine)
        $isDaemon = $arguments.Length -eq 4 -and $arguments[1] -eq 'daemon' -and $arguments[2] -eq '--install-slot' -and $arguments[3] -eq 'stable'
        $directDaemon = $directDaemon -or $isDaemon
        $rows += [pscustomobject]@{ pid = [int]$processId; image_name = [IO.Path]::GetFileName([string]$process.ExecutablePath); is_direct_daemon_mode = $isDaemon }
    }
    [pscustomobject]@{ processes = $rows; direct_daemon_present = $directDaemon }
}

function Invoke-MeshHealthObservationSelfTest {
    $digest = 'a' * 64
    $xmlDigest = 'b' * 64
    $imagePath = 'C:\fixture\mesh-daemon.exe'
    $expectedProcess = [pscustomobject]@{
        pid = 4242; creation_time_utc = '2026-08-14T12:00:00.0000000Z'
        image_path = $imagePath; image_sha256 = $digest; image_byte_length = 1234
        signature_status = 'NotSigned'; signer_certificate_sha256 = $null
    }
    $statusFactory = {
        param([bool]$Authenticated)
        [pscustomobject]@{
            exit_code = 0; stderr_bytes = 0; stderr_sha256 = $null
            body = [pscustomobject]@{
                kind='control_result'; operation='status'; ok=$true; lifecycle='ACTIVE'
                record=[pscustomobject]@{
                    health=[pscustomobject]@{ authenticated=$Authenticated; daemon_generation=if($Authenticated){7}else{$null}; daemon_state=if($Authenticated){'RUNNING'}else{$null}; diagnostic=if($Authenticated){$null}else{'HEALTH_UNAVAILABLE'} }
                    task=[pscustomobject]@{ state='RUNNING'; last_task_result=267009; running_instances=1; expected_definition_sha256=$digest; actual_definition_sha256=$digest }
                    runtime_integrity='EXACT'; runtime_expected_sha256=$digest; runtime_actual_sha256=$digest
                }
            }
        }
    }.GetNewClosure()
    $taskProbe = { [pscustomobject]@{ state='RUNNING'; last_task_result=267009; running_instance_pids=@(4242); xml_sha256=$xmlDigest } }.GetNewClosure()
    $identityProbe = { param($pid) if($pid-ne 4242){throw 'unexpected'}; $expectedProcess }.GetNewClosure()

    $clock = [pscustomobject]@{ value = 0L }
    $calls = [pscustomobject]@{ value = 0 }
    $delays = [Collections.Generic.List[int]]::new()
    $remainingBudgets = [Collections.Generic.List[int]]::new()
    $statusProbe = { param($remaining) $remainingBudgets.Add([int]$remaining); $calls.value++; & $statusFactory ($calls.value -ge 3) }.GetNewClosure()
    $now = { [long]$clock.value }.GetNewClosure()
    $delay = { param($milliseconds) $delays.Add([int]$milliseconds); $clock.value += $milliseconds }.GetNewClosure()
    $timeline = $null; $elapsed = 0L
    $result = Wait-AuthenticatedDaemonStatus -Runtime ignored -Cwd ignored -TaskPath ignored -ExpectedProcesses @($expectedProcess) -ExpectedImagePath $imagePath -ExpectedImageSha256 $digest -ExpectedTaskXmlSha256 $xmlDigest -ExpectedDefinitionSha256 $digest -Timeline ([ref]$timeline) -PollElapsedMs ([ref]$elapsed) -StatusProbe $statusProbe -TaskProbe $taskProbe -IdentityProbe $identityProbe -MonotonicMilliseconds $now -DelayAction $delay
    if (-not $result.body.record.health.authenticated -or @($timeline).Count -ne 3 -or $elapsed -ne 750 -or $delays.Count -ne 2 -or $delays[0] -ne 250 -or $delays[1] -ne 500 -or ($remainingBudgets -join ',') -ne '15000,14750,14250') { throw 'health poll success cadence self-test failed' }
    if ($timeline[0].probe_started_elapsed_ms -ne 0 -or $timeline[0].probe_duration_ms -ne 0 -or $timeline[1].monotonic_elapsed_ms -ne 250 -or $timeline[2].probe_completed_elapsed_ms -ne 750) { throw 'health poll monotonic evidence self-test failed' }
    if ($timeline[2].task.state -ne 'RUNNING' -or $timeline[2].task.last_task_result -ne 267009 -or $timeline[2].processes[0].creation_time_utc -ne $expectedProcess.creation_time_utc) { throw 'health poll identity evidence self-test failed' }

    $clock.value=0; $calls.value=0; $delays.Clear(); $remainingBudgets.Clear(); $timeline=$null; $elapsed=0L
    $statusProbe = { param($remaining) $remainingBudgets.Add([int]$remaining); $calls.value++; & $statusFactory $false }.GetNewClosure()
    $timedOut = $false
    try { [void](Wait-AuthenticatedDaemonStatus -Runtime ignored -Cwd ignored -TaskPath ignored -ExpectedProcesses @($expectedProcess) -ExpectedImagePath $imagePath -ExpectedImageSha256 $digest -ExpectedTaskXmlSha256 $xmlDigest -ExpectedDefinitionSha256 $digest -Timeline ([ref]$timeline) -PollElapsedMs ([ref]$elapsed) -StatusProbe $statusProbe -TaskProbe $taskProbe -IdentityProbe $identityProbe -MonotonicMilliseconds $now -DelayAction $delay) } catch { $timedOut = $_.Exception.Message -eq 'scheduled daemon did not publish authenticated health after fixture job close' }
    if (-not $timedOut -or $elapsed -ne 15000 -or @($timeline).Count -ne 31 -or $delays.Count -ne 31 -or $delays[0] -ne 250 -or $delays[1] -ne 500 -or $delays[$delays.Count-1] -ne 250 -or $remainingBudgets[0] -ne 15000 -or $remainingBudgets[$remainingBudgets.Count-1] -ne 250) { throw 'health poll absolute deadline self-test failed' }

    $clock.value=0; $calls.value=0; $delays.Clear(); $remainingBudgets.Clear(); $timeline=$null; $elapsed=0L
    $countBounded = $false
    try { [void](Wait-AuthenticatedDaemonStatus -Runtime ignored -Cwd ignored -TaskPath ignored -ExpectedProcesses @($expectedProcess) -ExpectedImagePath $imagePath -ExpectedImageSha256 $digest -ExpectedTaskXmlSha256 $xmlDigest -ExpectedDefinitionSha256 $digest -Timeline ([ref]$timeline) -PollElapsedMs ([ref]$elapsed) -TimeoutMs 5000 -MaximumObservations 2 -StatusProbe $statusProbe -TaskProbe $taskProbe -IdentityProbe $identityProbe -MonotonicMilliseconds $now -DelayAction $delay) } catch { $countBounded = $_.Exception.Message -eq 'health observation timeline exceeds its count bound' }
    if (-not $countBounded -or @($timeline).Count -ne 2 -or $calls.value -ne 2) { throw 'health observation count cap self-test failed' }

    $clock.value=0; $calls.value=0; $delays.Clear(); $remainingBudgets.Clear(); $timeline=$null; $elapsed=0L
    $byteBounded = $false
    try { [void](Wait-AuthenticatedDaemonStatus -Runtime ignored -Cwd ignored -TaskPath ignored -ExpectedProcesses @($expectedProcess) -ExpectedImagePath $imagePath -ExpectedImageSha256 $digest -ExpectedTaskXmlSha256 $xmlDigest -ExpectedDefinitionSha256 $digest -Timeline ([ref]$timeline) -PollElapsedMs ([ref]$elapsed) -TimeoutMs 5000 -MaximumTimelineBytes 1024 -StatusProbe $statusProbe -TaskProbe $taskProbe -IdentityProbe $identityProbe -MonotonicMilliseconds $now -DelayAction $delay) } catch { $byteBounded = $_.Exception.Message -eq 'health observation timeline exceeds its byte bound' }
    if (-not $byteBounded) { throw 'health observation byte cap self-test failed' }

    $clock.value=0; $calls.value=0; $delays.Clear(); $remainingBudgets.Clear(); $timeline=$null; $elapsed=0L
    $ambiguousTaskProbe = { [pscustomobject]@{ state='RUNNING'; last_task_result=267009; running_instance_pids=@(9999); xml_sha256=$xmlDigest } }.GetNewClosure()
    $ambiguous = $false
    try { [void](Wait-AuthenticatedDaemonStatus -Runtime ignored -Cwd ignored -TaskPath ignored -ExpectedProcesses @($expectedProcess) -ExpectedImagePath $imagePath -ExpectedImageSha256 $digest -ExpectedTaskXmlSha256 $xmlDigest -ExpectedDefinitionSha256 $digest -Timeline ([ref]$timeline) -PollElapsedMs ([ref]$elapsed) -StatusProbe $statusProbe -TaskProbe $ambiguousTaskProbe -IdentityProbe $identityProbe -MonotonicMilliseconds $now -DelayAction $delay) } catch { $ambiguous = $_.Exception.Message -match 'identity observation is ambiguous' }
    if (-not $ambiguous -or @($timeline).Count -ne 1 -or $timeline[0].identity_ambiguity -ne 'UNEXPECTED_TASK_PID') { throw 'health identity ambiguity self-test failed' }

    [pscustomobject]@{ self_test='health-observation-v1'; outcome='PASS'; cadence_ms=@(250,500); absolute_deadline_ms=15000; maximum_observations=32; maximum_timeline_bytes=131072; identity_ambiguity='FAIL_CLOSED' } | ConvertTo-Json -Compress
}

if ($SelfTest) {
    Invoke-MeshHealthObservationSelfTest
    exit 0
}

$runId = 'job-' + [Guid]::NewGuid().ToString('N')
$startedAt = [DateTimeOffset]::UtcNow
$layout = $null
$createdInstallId = $null
$createdTaskPath = $null
$createdDefinitionDigest = $null
$removed = $false
$outcome = 'FAIL'
$reason = $null
$evidence = [ordered]@{}
$cleanup = [ordered]@{ attempted = $false; exact_owner_verified = $false; task_removed = $false; retained_data = $false; residual = @() }

try {
    $hostEvidence = Get-MeshFixtureHostEvidence
    $evidence.host = $hostEvidence
    $capability = Get-MeshFixtureCapability -HostEvidence $hostEvidence
    if ($capability) {
        $outcome = 'NOT_RUN'; $reason = $capability
    } else {
        Add-Type -Path (Join-Path $fixtureRoot 'JobHarness.cs')
        $sourceRuntime = Get-MeshRuntimePath -RepositoryRoot $repositoryRoot -RuntimePath $RuntimePath -SkipBuild:$SkipBuild
        $layout = New-MeshFixtureLayout -SourceRuntime $sourceRuntime -RunId $runId
        $sourceEvidence = Get-MeshRuntimeEvidence -Path $layout.runtime
        $evidence.fixture = [ordered]@{ ownership_marker = $runId; runtime = $sourceEvidence; arbitrary_cwd = $true; spaces_unicode = $true }

        $initial = Invoke-MeshControl -RuntimePath $layout.runtime -Operation status -WorkingDirectory $layout.caller
        $evidence.initial_status = $initial.body
        if ($initial.exit_code -ne 0) { throw 'initial installation status failed' }
        if ($initial.body.lifecycle -notin @('ABSENT','RETAINED')) {
            $outcome = 'NOT_RUN'; $reason = 'PREEXISTING_ACTIVE_OR_DRIFTED_INSTALLATION_PRESERVED'
            $evidence.preservation = [ordered]@{ mutated = $false; lifecycle = $initial.body.lifecycle }
        } else {
            if ($initial.body.lifecycle -eq 'RETAINED') {
                $existing = Get-MeshInstallRecord
                if (-not $existing -or [string]$existing.record.runtime.sha256 -ne $sourceEvidence.sha256) {
                    $outcome = 'NOT_RUN'; $reason = 'RETAINED_INSTALLATION_DIGEST_MISMATCH_PRESERVED'
                }
            }
            if (-not $reason) {
                $setup = Invoke-MeshControl -RuntimePath $layout.runtime -Operation setup -WorkingDirectory $layout.caller
                $evidence.setup = $setup.body
                if ($setup.exit_code -ne 0 -or -not $setup.body.ok) {
                    if ($setup.body.error.code -in @('SETUP_ACCESS_DENIED','SETUP_DISABLED')) { $outcome='NOT_RUN'; $reason='JOB_FIXTURE_PRIVILEGE_OR_INTERACTIVE_TOKEN_UNAVAILABLE' }
                    else { throw 'setup failed before job exercise' }
                } else {
                    $createdInstallId = [string]$setup.body.install_id
                    $recordEnvelope = Get-MeshInstallRecord
                    $record = $recordEnvelope.record
                    $createdTaskPath = [string]$record.scheduled_task.task_path
                    $createdDefinitionDigest = [string]$record.scheduled_task.definition_sha256
                    $task = Get-MeshTaskEvidence -TaskPath $createdTaskPath
                    if (-not $task -or -not (Test-MeshExactTaskOwnership -Record $record -Task $task -CurrentSid $hostEvidence.user_sid)) { throw 'exact task ownership could not be proven' }
                    if ($task.logon_type -ne 3 -or $task.run_level -ne 0 -or -not $task.enabled -or
                        $task.working_directory -ne [IO.Path]::GetDirectoryName($task.action_path)) { throw 'task principal, run level, enabled state, or working directory drifted' }
                    $stableRuntime = Get-MeshRuntimeEvidence -Path $task.action_path
                    if ($stableRuntime.sha256 -ne [string]$record.runtime.sha256) { throw 'scheduled action runtime digest drifted' }
                    $statusBeforeJob = Invoke-MeshControl -RuntimePath $layout.runtime -Operation status -WorkingDirectory $layout.caller
                    if ($statusBeforeJob.exit_code -ne 0 -or
                        $statusBeforeJob.body.record.task.expected_definition_sha256 -ne $createdDefinitionDigest -or
                        $statusBeforeJob.body.record.task.actual_definition_sha256 -ne $createdDefinitionDigest) { throw 'production task definition read-back digest drifted' }
                    $evidence.ownership = [ordered]@{
                        task_name=$task.name; task_path=$createdTaskPath; owner_uri=$task.owner_uri
                        definition_sha256=$createdDefinitionDigest; task_xml_sha256=$task.xml_sha256
                        runtime_sha256=$stableRuntime.sha256; signature_status=$stableRuntime.signature_status
                        principal_sid=$task.user_sid; trigger_count=$task.trigger_count; action_count=$task.action_count
                    }

                    $startReady = Join-Path $layout.root 'mid-start.ready'
                    $startBreakaway = Join-Path $layout.root 'mid-start.breakaway.json'
                    $startCompletion = Join-Path $layout.root 'mid-start.complete.json'
                    try { $startJob = New-JobChild -Mode start -Runtime $layout.runtime -Cwd $layout.caller -ReadyPath $startReady -BreakawayPath $startBreakaway -CompletionPath $startCompletion }
                    catch [ComponentModel.Win32Exception] { $outcome='NOT_RUN'; $reason='NONBREAKAWAY_JOB_ASSIGNMENT_UNAVAILABLE'; throw [OperationCanceledException]::new($reason) }
                    try {
                        $startMarker = Wait-FixtureFile -Path $startReady
                        $breakaway = (Wait-FixtureFile -Path $startBreakaway) | ConvertFrom-Json
                        $controlPid = [int]($startMarker -split ':',2)[1]
                        $runningTask = Wait-TaskInstance -TaskPath $createdTaskPath -CompletionPath $startCompletion
                        $processIdentityCache = @{}
                        $daemonProcesses = @($runningTask.running_instance_pids | ForEach-Object {
                            Get-MeshScheduledDaemonProcessEvidence -ProcessId ([int]$_) -ExpectedImagePath $task.action_path -ExpectedImageSha256 $stableRuntime.sha256 -Cache $processIdentityCache
                        })
                        if ($daemonProcesses.Count -ne $runningTask.running_instance_pids.Count) { throw 'scheduled daemon process identity observation is ambiguous' }
                        if (-not [MeshFixtureNative]::IsProcessInSpecificJob($startJob.ProcessId,$startJob.JobHandle)) { throw 'fixture parent was not assigned to its job' }
                        if (-not [MeshFixtureNative]::IsProcessInSpecificJob($controlPid,$startJob.JobHandle)) { throw 'start helper escaped the fixture job' }
                        try { $jobProcesses = Get-FixtureJobProcessEvidence -Job $startJob }
                        catch [UnauthorizedAccessException] { $outcome='NOT_RUN'; $reason='FIXTURE_PROCESS_INSPECTION_PRIVILEGE_REQUIRED'; throw [OperationCanceledException]::new($reason) }
                        if ($jobProcesses.direct_daemon_present) { throw 'a direct daemon-mode fallback appeared inside the fixture job' }
                        $daemonMembership = @($runningTask.running_instance_pids | ForEach-Object { [MeshFixtureNative]::IsProcessInSpecificJob([int]$_,$startJob.JobHandle) })
                        if ($daemonMembership -contains $true) { throw 'scheduled daemon remained in fixture job (direct-child fallback suspected)' }
                        if ([int]$breakaway.win32_error -ne 5) { throw "explicit breakaway control did not fail with access denied: $($breakaway.win32_error)" }
                        $evidence.mid_start = [ordered]@{
                            fixture_pid = $startJob.ProcessId
                            control_pid = $controlPid
                            helper_in_fixture_job = $true
                            daemon_instance_pids = $runningTask.running_instance_pids
                            daemon_processes = $daemonProcesses
                            daemon_in_fixture_job = $daemonMembership
                            explicit_breakaway_win32_error = [int]$breakaway.win32_error
                            job_processes = $jobProcesses.processes
                            direct_daemon_fallback_present = $false
                            job_closed = $false
                            authenticated_health_after_close = $null
                            health_poll_elapsed_ms = $null
                            health_observation_timeline = @()
                        }
                        $startJob.CloseJob()
                        $evidence.mid_start.job_closed = $true
                        Start-Sleep -Milliseconds 100
                        if (Get-Process -Id $startJob.ProcessId -ErrorAction SilentlyContinue) { throw 'KILL_ON_JOB_CLOSE did not terminate the fixture parent' }
                        if (Get-Process -Id $controlPid -ErrorAction SilentlyContinue) { throw 'KILL_ON_JOB_CLOSE did not terminate the start helper' }
                        $healthTimeline = $null
                        $healthPollElapsed = 0L
                        try {
                            $healthyAfterStartKill = Wait-AuthenticatedDaemonStatus -Runtime $layout.runtime -Cwd $layout.caller -TaskPath $createdTaskPath -ExpectedProcesses $daemonProcesses -ExpectedImagePath $task.action_path -ExpectedImageSha256 $stableRuntime.sha256 -ExpectedTaskXmlSha256 $runningTask.xml_sha256 -ExpectedDefinitionSha256 $createdDefinitionDigest -Timeline ([ref]$healthTimeline) -PollElapsedMs ([ref]$healthPollElapsed)
                            $evidence.mid_start.authenticated_health_after_close = $healthyAfterStartKill.body.record.health
                        } finally {
                            $evidence.mid_start.health_poll_elapsed_ms = $healthPollElapsed
                            $evidence.mid_start.health_observation_timeline = @($healthTimeline)
                        }
                    } finally { if ($startJob) { $startJob.Dispose() } }

                    $baseCommit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
                    if ($LASTEXITCODE -ne 0) { throw 'fixture could not resolve a base commit' }
                    $commandKey = 'fixture-' + [Guid]::NewGuid().ToString('N')
                    $delegate = Invoke-MeshRpcOnce -RuntimePath $layout.runtime -WorkingDirectory $layout.caller -Request ([ordered]@{
                        jsonrpc='2.0'; id='fixture-delegate'; method='mesh.delegate_task'; params=[ordered]@{
                            version=1; kind='task_request'; command_key=$commandKey; role='research'; objective='Hold a queued task for the non-breakaway wait fixture.'; context_refs=@(); quality='standard'; effort='medium'; timeout_seconds=300; priority=0;
                            workspace=[ordered]@{ path=$repositoryRoot; base_commit=$baseCommit; mode='read_only' }; effect_profile='READ_ONLY'; permission_policy='deny_writes'; review_chain_override='disabled'
                        }
                    })
                    if (-not $delegate.result -or $delegate.result.kind -ne 'delegate_task_result') { throw 'fixture task delegation failed' }
                    $taskId = [string]$delegate.result.task.task_id
                    $inspect = Invoke-MeshRpcOnce -RuntimePath $layout.runtime -WorkingDirectory $layout.caller -Request ([ordered]@{ jsonrpc='2.0'; id='fixture-inspect'; method='mesh.inspect_task'; params=@{ task_id=$taskId } })
                    $afterSeq = [long]$inspect.result.cursor.last_committed_seq

                    $rpcReady = Join-Path $layout.root 'mid-rpc.ready'
                    $rpcBreakaway = Join-Path $layout.root 'mid-rpc.breakaway.json'
                    $rpcCompletion = Join-Path $layout.root 'mid-rpc.complete'
                    $rpcJob = New-JobChild -Mode wait -Runtime $layout.runtime -Cwd $layout.caller -ReadyPath $rpcReady -BreakawayPath $rpcBreakaway -CompletionPath $rpcCompletion -TaskId $taskId -AfterSeq $afterSeq
                    try {
                        $rpcMarker = Wait-FixtureFile -Path $rpcReady
                        $rpcBreakawayEvidence = (Wait-FixtureFile -Path $rpcBreakaway) | ConvertFrom-Json
                        $bridgePid = [int]($rpcMarker -split ':',2)[1]
                        Start-Sleep -Milliseconds 250
                        if (Test-Path -LiteralPath $rpcCompletion -PathType Leaf) { throw 'wait_task replied before the kill boundary; mid-RPC was not exercised' }
                        if (-not [MeshFixtureNative]::IsProcessInSpecificJob($rpcJob.ProcessId,$rpcJob.JobHandle) -or -not [MeshFixtureNative]::IsProcessInSpecificJob($bridgePid,$rpcJob.JobHandle)) { throw 'RPC helper or bridge escaped the fixture job' }
                        try { $jobProcesses = Get-FixtureJobProcessEvidence -Job $rpcJob }
                        catch [UnauthorizedAccessException] { $outcome='NOT_RUN'; $reason='FIXTURE_PROCESS_INSPECTION_PRIVILEGE_REQUIRED'; throw [OperationCanceledException]::new($reason) }
                        if ($jobProcesses.direct_daemon_present) { throw 'a direct daemon-mode fallback appeared during RPC' }
                        $runningTask = Wait-TaskInstance -TaskPath $createdTaskPath
                        $daemonMembership = @($runningTask.running_instance_pids | ForEach-Object { [MeshFixtureNative]::IsProcessInSpecificJob([int]$_,$rpcJob.JobHandle) })
                        if ($daemonMembership -contains $true) { throw 'daemon entered the mid-RPC fixture job' }
                        if ([int]$rpcBreakawayEvidence.win32_error -ne 5) { throw 'mid-RPC direct breakaway control unexpectedly succeeded' }
                        $evidence.mid_rpc = [ordered]@{
                            fixture_pid = $rpcJob.ProcessId
                            bridge_pid = $bridgePid
                            fixture_and_bridge_in_job = $true
                            daemon_instance_pids = $runningTask.running_instance_pids
                            daemon_in_fixture_job = $daemonMembership
                            wait_task_id_sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($taskId))).ToLowerInvariant()
                            explicit_breakaway_win32_error = [int]$rpcBreakawayEvidence.win32_error
                            job_processes = $jobProcesses.processes
                            direct_daemon_fallback_present = $false
                            job_closed = $false
                            authenticated_health_after_close = $null
                            durable_task_state_after_close = $null
                        }
                        $rpcJob.CloseJob()
                        $evidence.mid_rpc.job_closed = $true
                        Start-Sleep -Milliseconds 100
                        if (Get-Process -Id $rpcJob.ProcessId -ErrorAction SilentlyContinue) { throw 'mid-RPC fixture survived KILL_ON_JOB_CLOSE' }
                        if (Get-Process -Id $bridgePid -ErrorAction SilentlyContinue) { throw 'mid-RPC bridge survived KILL_ON_JOB_CLOSE' }
                        $healthAfterRpcKill = Invoke-MeshControl -RuntimePath $layout.runtime -Operation start -WorkingDirectory $layout.caller
                        $taskAfterRpcKill = Invoke-MeshRpcOnce -RuntimePath $layout.runtime -WorkingDirectory $layout.caller -Request ([ordered]@{ jsonrpc='2.0'; id='fixture-post-kill'; method='mesh.inspect_task'; params=@{ task_id=$taskId } })
                        if ($healthAfterRpcKill.exit_code -ne 0 -or -not $healthAfterRpcKill.body.health.authenticated -or $taskAfterRpcKill.result.task.task_id -ne $taskId) { throw 'daemon/task health did not survive the mid-RPC helper death' }
                        $evidence.mid_rpc.authenticated_health_after_close = $healthAfterRpcKill.body.health
                        $evidence.mid_rpc.durable_task_state_after_close = $taskAfterRpcKill.result.task.state
                    } finally { if ($rpcJob) { $rpcJob.Dispose() } }

                    $finalStatus = Invoke-MeshControl -RuntimePath $layout.runtime -Operation status -WorkingDirectory $layout.caller
                    if ($finalStatus.body.record.task.expected_definition_sha256 -ne $createdDefinitionDigest -or $finalStatus.body.record.task.actual_definition_sha256 -ne $createdDefinitionDigest) { throw 'task definition drifted before cleanup' }
                    $remove = Invoke-MeshControl -RuntimePath $layout.runtime -Operation remove -WorkingDirectory $layout.caller
                    if ($remove.exit_code -ne 0 -or $remove.body.lifecycle -ne 'RETAINED') { throw 'exact task cleanup failed' }
                    $removed = $true
                    $cleanup.attempted = $true; $cleanup.exact_owner_verified = $true; $cleanup.retained_data = $true
                    $cleanup.task_removed = -not [bool](Get-MeshTaskEvidence -TaskPath $createdTaskPath)
                    if (-not $cleanup.task_removed) { throw 'exact task remained after removal' }
                    $outcome = 'PASS'
                }
            }
        }
    }
} catch [OperationCanceledException] {
    if ($outcome -ne 'NOT_RUN') { $outcome='FAIL'; $reason=$_.Exception.Message }
} catch {
    $outcome='FAIL'; $reason=$_.Exception.Message
} finally {
    if ($createdInstallId -and -not $removed -and $layout) {
        $cleanup.attempted = $true
        try {
            $current = Get-MeshInstallRecord
            $task = if ($current -and $createdTaskPath) { Get-MeshTaskEvidence -TaskPath $createdTaskPath } else { $null }
            $exact = $current -and [string]$current.record.install_id -eq $createdInstallId -and [string]$current.record.scheduled_task.task_path -eq $createdTaskPath -and [string]$current.record.scheduled_task.definition_sha256 -eq $createdDefinitionDigest -and $task -and (Test-MeshExactTaskOwnership -Record $current.record -Task $task -CurrentSid $evidence.host.user_sid)
            $cleanup.exact_owner_verified = [bool]$exact
            if ($exact) {
                $status = Invoke-MeshControl -RuntimePath $layout.runtime -Operation status -WorkingDirectory $layout.caller
                if ($status.exit_code -eq 0 -and $status.body.PSObject.Properties['record'] -and $status.body.record.task.actual_definition_sha256 -eq $createdDefinitionDigest) {
                    $remove = Invoke-MeshControl -RuntimePath $layout.runtime -Operation remove -WorkingDirectory $layout.caller
                    $cleanup.task_removed = $remove.exit_code -eq 0 -and $remove.body.lifecycle -eq 'RETAINED'; $cleanup.retained_data = $cleanup.task_removed
                } else { $cleanup.residual += 'drifted task preserved; manual action required' }
            } else { $cleanup.residual += 'unknown ownership preserved; no delete attempted' }
        } catch { $cleanup.residual += "cleanup error: $($_.Exception.Message)" }
    }
    if ($layout -and (Test-Path -LiteralPath $layout.root)) {
        try { Remove-MeshFixtureLayout -Layout $layout } catch { $cleanup.residual += "temporary cleanup error: $($_.Exception.Message)" }
    }
}

$report = [ordered]@{ fixture='nonbreakaway-job-v1'; run_id=$runId; outcome=$outcome; reason=$reason; started_at_utc=$startedAt.ToString('O'); duration_ms=[int]([DateTimeOffset]::UtcNow-$startedAt).TotalMilliseconds; evidence=$evidence; cleanup=$cleanup }
$report | ConvertTo-Json -Depth 64
if ($outcome -eq 'PASS') { exit 0 }
if ($outcome -eq 'NOT_RUN' -and -not $Strict) { exit 0 }
exit 1
