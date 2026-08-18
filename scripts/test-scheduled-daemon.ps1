param(
    [string]$RuntimePath,
    [switch]$SkipBuild,
    [switch]$Strict
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $repositoryRoot 'tests\process-fixtures\scheduled-job\LiveFixture.Common.ps1')

$runId = 'scheduled-' + [Guid]::NewGuid().ToString('N')
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
        $outcome = 'NOT_RUN'
        $reason = $capability
    } else {
        $sourceRuntime = Get-MeshRuntimePath -RepositoryRoot $repositoryRoot -RuntimePath $RuntimePath -SkipBuild:$SkipBuild
        $layout = New-MeshFixtureLayout -SourceRuntime $sourceRuntime -RunId $runId
        $runtimeEvidence = Get-MeshRuntimeEvidence -Path $layout.runtime
        $evidence.fixture = [ordered]@{
            ownership_marker = $runId
            cache_path_has_spaces = $layout.runtime.Contains(' ')
            cache_path_has_unicode = $layout.root.Contains('Ω')
            caller_cwd_has_spaces = $layout.caller.Contains(' ')
            caller_cwd_has_unicode = $layout.caller.Contains('雪')
            runtime = $runtimeEvidence
        }

        $initial = Invoke-MeshControl -RuntimePath $layout.runtime -Operation status -WorkingDirectory $layout.caller
        $evidence.initial_status = $initial.body
        if ($initial.exit_code -ne 0) { throw "initial status failed with exit $($initial.exit_code)" }
        if ($initial.body.lifecycle -ne 'ABSENT') {
            $outcome = 'NOT_RUN'
            $reason = 'PREEXISTING_STABLE_INSTALLATION_PRESERVED'
            $evidence.preservation = [ordered]@{ mutated = $false; lifecycle = $initial.body.lifecycle }
        } else {
            $setup = Invoke-MeshControl -RuntimePath $layout.runtime -Operation setup -WorkingDirectory $layout.caller
            $evidence.setup = $setup.body
            if ($setup.exit_code -ne 0 -or -not $setup.body.ok -or $setup.body.lifecycle -ne 'ACTIVE') {
                if ($setup.body.error.code -in @('SETUP_ACCESS_DENIED','SETUP_DISABLED')) {
                    $outcome = 'NOT_RUN'
                    $reason = 'INTERACTIVE_TASK_FIXTURE_UNAVAILABLE'
                } else {
                    throw "setup failed with exit $($setup.exit_code)"
                }
            } else {
                $createdInstallId = [string]$setup.body.install_id
                $recordEnvelope = Get-MeshInstallRecord
                if (-not $recordEnvelope) { throw 'setup succeeded without an install record' }
                $record = $recordEnvelope.record
                if ([string]$record.install_id -ne $createdInstallId) { throw 'setup/install-record identity mismatch' }
                $createdTaskPath = [string]$record.scheduled_task.task_path
                $createdDefinitionDigest = [string]$record.scheduled_task.definition_sha256
                $task = Get-MeshTaskEvidence -TaskPath $createdTaskPath
                if (-not $task) { throw 'setup succeeded without the exact recorded task' }
                if (-not (Test-MeshExactTaskOwnership -Record $record -Task $task -CurrentSid $hostEvidence.user_sid)) { throw 'task COM read-back did not match exact ownership' }
                if ($task.logon_type -ne 3 -or $task.run_level -ne 0 -or -not $task.enabled -or
                    $task.working_directory -ne [IO.Path]::GetDirectoryName($task.action_path)) { throw 'task principal, run level, enabled state, or working directory drifted' }
                $stableRuntime = Get-MeshRuntimeEvidence -Path $task.action_path
                if ($stableRuntime.sha256 -ne [string]$record.runtime.sha256) { throw 'task action runtime digest drifted' }

                $postSetup = Invoke-MeshControl -RuntimePath $layout.runtime -Operation status -WorkingDirectory $layout.caller
                if ($postSetup.exit_code -ne 0 -or $postSetup.body.record.task.state -notin @('READY','RUNNING')) { throw 'post-setup task status is not startable' }
                $taskStatus = $postSetup.body.record.task
                if ($taskStatus.expected_definition_sha256 -ne $createdDefinitionDigest -or
                    $taskStatus.actual_definition_sha256 -ne $createdDefinitionDigest) { throw 'production definition read-back digest mismatch' }
                $evidence.owned_task = [ordered]@{
                    task_name = $task.name
                    task_path = $task.path
                    owner_uri = $task.owner_uri
                    definition_sha256 = $createdDefinitionDigest
                    task_xml_sha256 = $task.xml_sha256
                    runtime_sha256 = $stableRuntime.sha256
                    signature_status = $stableRuntime.signature_status
                    principal_sid = $task.user_sid
                    logon_type = $task.logon_type
                    run_level = $task.run_level
                    trigger_count = $task.trigger_count
                    action_count = $task.action_count
                    action_arguments = $task.action_arguments
                    execution_time_limit = $task.execution_time_limit
                }

                $start = Invoke-MeshControl -RuntimePath $layout.runtime -Operation start -WorkingDirectory $layout.caller
                $evidence.start = $start.body
                if ($start.exit_code -ne 0 -or -not $start.body.ok -or -not $start.body.health.authenticated -or $start.body.health.daemon_state -ne 'RUNNING') { throw 'demand start did not reach authenticated RUNNING health' }
                $running = Invoke-MeshControl -RuntimePath $layout.runtime -Operation status -WorkingDirectory $layout.caller
                $evidence.running_status = $running.body
                if ($running.exit_code -ne 0 -or -not $running.body.record.health.authenticated -or $running.body.record.health.daemon_state -ne 'RUNNING') { throw 'status did not read back authenticated daemon health' }

                $remove = Invoke-MeshControl -RuntimePath $layout.runtime -Operation remove -WorkingDirectory $layout.caller
                $evidence.remove = $remove.body
                if ($remove.exit_code -ne 0 -or -not $remove.body.ok -or $remove.body.lifecycle -ne 'RETAINED') { throw 'exact owned task removal failed' }
                $removed = $true
                $cleanup.attempted = $true
                $cleanup.exact_owner_verified = $true
                $cleanup.retained_data = [bool]$remove.body.retained_data
                $cleanup.task_removed = -not [bool](Get-MeshTaskEvidence -TaskPath $createdTaskPath)
                if (-not $cleanup.task_removed) { throw 'removed task remained visible by its exact recorded path' }
                $retained = Invoke-MeshControl -RuntimePath $layout.runtime -Operation status -WorkingDirectory $layout.caller
                if ($retained.exit_code -ne 0 -or $retained.body.lifecycle -ne 'RETAINED') { throw 'retained lifecycle read-back failed' }
                $evidence.retained_status = $retained.body
                $outcome = 'PASS'
            }
        }
    }
} catch {
    $outcome = 'FAIL'
    $reason = $_.Exception.Message
} finally {
    if ($createdInstallId -and -not $removed -and $layout) {
        $cleanup.attempted = $true
        try {
            $current = Get-MeshInstallRecord
            $task = if ($current -and $createdTaskPath) { Get-MeshTaskEvidence -TaskPath $createdTaskPath } else { $null }
            $exact = $current -and
                [string]$current.record.install_id -eq $createdInstallId -and
                [string]$current.record.scheduled_task.task_path -eq $createdTaskPath -and
                [string]$current.record.scheduled_task.definition_sha256 -eq $createdDefinitionDigest -and
                $task -and
                (Test-MeshExactTaskOwnership -Record $current.record -Task $task -CurrentSid $evidence.host.user_sid)
            $cleanup.exact_owner_verified = [bool]$exact
            if ($exact) {
                $status = Invoke-MeshControl -RuntimePath $layout.runtime -Operation status -WorkingDirectory $layout.caller
                if ($status.exit_code -eq 0 -and $status.body.PSObject.Properties['record'] -and
                    $status.body.record.task.expected_definition_sha256 -eq $createdDefinitionDigest -and
                    $status.body.record.task.actual_definition_sha256 -eq $createdDefinitionDigest) {
                    $remove = Invoke-MeshControl -RuntimePath $layout.runtime -Operation remove -WorkingDirectory $layout.caller
                    $cleanup.task_removed = $remove.exit_code -eq 0 -and $remove.body.lifecycle -eq 'RETAINED'
                    $cleanup.retained_data = $cleanup.task_removed
                } else {
                    $cleanup.residual += 'definition digest drifted; exact task was preserved'
                }
            } else {
                $cleanup.residual += 'ownership changed or task drifted; no deletion attempted'
            }
        } catch {
            $cleanup.residual += "cleanup error: $($_.Exception.Message)"
        }
    }
    if ($layout -and (Test-Path -LiteralPath $layout.root)) {
        try { Remove-MeshFixtureLayout -Layout $layout } catch { $cleanup.residual += "temporary cleanup error: $($_.Exception.Message)" }
    }
}

$report = [ordered]@{
    fixture = 'scheduled-daemon-v1'
    run_id = $runId
    outcome = $outcome
    reason = $reason
    started_at_utc = $startedAt.ToString('O')
    duration_ms = [int]([DateTimeOffset]::UtcNow - $startedAt).TotalMilliseconds
    evidence = $evidence
    cleanup = $cleanup
}
$report | ConvertTo-Json -Depth 64
if ($outcome -eq 'PASS') { exit 0 }
if ($outcome -eq 'NOT_RUN' -and -not $Strict) { exit 0 }
exit 1
