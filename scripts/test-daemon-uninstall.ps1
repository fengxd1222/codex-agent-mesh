[CmdletBinding()]
param(
    [string]$RuntimePath,
    [switch]$RequireFixture,
    [ValidateRange(1, 32)]
    [int]$ReconnectClients = 8,
    [ValidateRange(15, 120)]
    [int]$ProcessTimeoutSeconds = 45
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$fixtureId = [guid]::NewGuid().ToString("N")
$knownLocalAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
$productRoot = [IO.Path]::GetFullPath((Join-Path $knownLocalAppData "codex-agent-mesh"))
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ("codex agent mesh uninstall {0} 雪" -f $fixtureId)
$bundleRoot = Join-Path $fixtureRoot "bundle cache with spaces 雪"
$callerRoot = Join-Path $fixtureRoot "caller cwd with spaces 雪"
$spoofedLocalAppData = Join-Path $fixtureRoot "spoofed LOCALAPPDATA 雪"
$fixtureMarkerPath = Join-Path $fixtureRoot "fixture-owner.json"
$recordPath = Join-Path $productRoot "slots\stable\install.json"
$trackedProcesses = [Collections.Generic.Dictionary[int, object]]::new()
$ownedInstallId = $null
$ownedTaskName = $null
$stableRuntimePath = $null
$runtimeDigest = $null
$daemonPid = $null
$daemonLockBlocker = $null
$recordBlocker = $null
$blockingBridge = $null
$baseline = $null
$record = $null
$initialTask = $null
$collisionDefinition = $null
$fixtureTaskMutationMarker = "--fixture-drift-$fixtureId"
$productRootExistedBefore = Test-Path -LiteralPath $productRoot
$setupStarted = $false
$ownershipBound = $false
$ownedInitialRecordDigest = $null
$ownedConsumerId = $null
$ownedTaskDefinitionDigest = $null
$ownedTaskXmlDigests = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$cleanup = [ordered]@{
    taskAbsent = $null
    productRootRemoved = $null
    temporaryRootRemoved = $null
    retainedSideEffects = @()
}
$checks = [Collections.Generic.List[string]]::new()
$timelines = [Collections.Generic.List[object]]::new()
$failure = $null

function Get-Sha256String([string]$Value) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([Convert]::ToHexString($algorithm.ComputeHash($bytes))).ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Get-Sha256Bytes([byte[]]$Bytes) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([Convert]::ToHexString($algorithm.ComputeHash($Bytes))).ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-TreeDigest([string]$Root) {
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "Required retained tree is absent."
    }
    $entries = @(
        Get-ChildItem -LiteralPath $Root -Force -Recurse -File |
            ForEach-Object {
                [ordered]@{
                    relative = $_.FullName.Substring($Root.Length).TrimStart('\').Replace('\', '/')
                    length = $_.Length
                    sha256 = Get-FileSha256 $_.FullName
                }
            } |
            Sort-Object relative
    )
    return Get-Sha256String (($entries | ConvertTo-Json -Compress -Depth 4) -join "")
}

function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -ne $Expected) {
        throw "$Message (expected '$Expected', observed '$Actual')"
    }
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Test-ExactDescendant([string]$Candidate, [string]$Root) {
    $fullCandidate = [IO.Path]::GetFullPath($Candidate).TrimEnd('\')
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    return $fullCandidate.StartsWith($fullRoot + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Read-InstallRecord {
    if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
        return $null
    }
    return Get-Content -Raw -LiteralPath $recordPath | ConvertFrom-Json
}

function Read-InstallRecordEvidence {
    if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) {
        return $null
    }
    $bytes = [IO.File]::ReadAllBytes($recordPath)
    $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    return [pscustomobject]@{
        Record = $text | ConvertFrom-Json
        Sha256 = Get-Sha256Bytes $bytes
    }
}

function Assert-OwnedRecord($Record) {
    Assert-True ($null -ne $Record) "The fixture install record is absent."
    Assert-Equal $Record.install_id $ownedInstallId "The install identity changed."
    Assert-True ($Record.install_id -match '^[0-9a-f]{32}$') "The install identity is malformed."
    Assert-True ($Record.consumer_id -match '^[0-9a-f]{32}$') "The consumer identity is malformed."
}

function Assert-OwnedStableTuple($Record) {
    Assert-OwnedRecord $Record
    Assert-True $ownershipBound "Fixture ownership was never bound."
    Assert-Equal $Record.consumer_id $ownedConsumerId "The bound consumer identity changed."
    Assert-Equal $Record.product_relative_path ("installs\$ownedInstallId") "The bound product path changed."
    Assert-Equal $Record.data_relative_path $baseline.DataRelativePath "The bound data path changed."
    Assert-Equal $Record.protected_key.relative_path $baseline.KeyRelativePath "The bound key path changed."
    Assert-Equal $Record.protected_key.sha256 $baseline.KeyDigest "The bound key digest changed."
    Assert-Equal $Record.runtime.relative_path $baseline.RuntimeRelativePath "The bound runtime path changed."
    Assert-Equal $Record.runtime.sha256 $baseline.RuntimeDigest "The bound runtime digest changed."
    Assert-Equal $Record.scheduled_task.task_path ("\$ownedTaskName") "The bound task path changed."
    Assert-Equal $Record.scheduled_task.definition_sha256 $ownedTaskDefinitionDigest "The bound task definition digest changed."
}

function New-ProcessStartInfo([string]$Executable, [string[]]$Arguments, [bool]$RedirectInput) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = [IO.Path]::GetFullPath($Executable)
    $info.WorkingDirectory = $callerRoot
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.RedirectStandardInput = $RedirectInput
    foreach ($argument in $Arguments) {
        [void]$info.ArgumentList.Add($argument)
    }
    $info.Environment['LOCALAPPDATA'] = $spoofedLocalAppData
    return $info
}

function Start-OwnedProcess(
    [string]$Executable,
    [string[]]$Arguments,
    [bool]$RedirectInput = $false
) {
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = New-ProcessStartInfo $Executable $Arguments $RedirectInput
    if (-not $process.Start()) {
        throw "Fixture child creation failed."
    }
    $owned = [pscustomobject]@{
        Process = $process
        Executable = [IO.Path]::GetFullPath($Executable)
        ExecutableDigest = Get-FileSha256 $Executable
        StartedAt = $process.StartTime.ToUniversalTime()
        StdoutTask = $process.StandardOutput.ReadToEndAsync()
        StderrTask = $process.StandardError.ReadToEndAsync()
    }
    $trackedProcesses.Add($process.Id, $owned)
    return $owned
}

function Assert-OwnedProcessIdentity($Owned) {
    if ($Owned.Process.HasExited) {
        return
    }
    $current = Get-Process -Id $Owned.Process.Id -ErrorAction Stop
    Assert-Equal $current.StartTime.ToUniversalTime() $Owned.StartedAt "Tracked PID was reused."
    if ($current.Path) {
        Assert-Equal ([IO.Path]::GetFullPath($current.Path)) $Owned.Executable "Tracked process image changed."
        Assert-Equal (Get-FileSha256 $current.Path) $Owned.ExecutableDigest "Tracked process digest changed."
    }
}

function Stop-OwnedProcess($Owned) {
    if (-not $Owned.Process.HasExited) {
        Assert-OwnedProcessIdentity $Owned
        $Owned.Process.Kill()
        if (-not $Owned.Process.WaitForExit(5000)) {
            throw "Exact fixture child did not terminate after kill."
        }
    }
}

function Complete-OwnedProcess($Owned, [int]$TimeoutSeconds = $ProcessTimeoutSeconds) {
    if (-not $Owned.Process.WaitForExit($TimeoutSeconds * 1000)) {
        Stop-OwnedProcess $Owned
        throw "Fixture child exceeded its bounded deadline."
    }
    $stdout = $Owned.StdoutTask.GetAwaiter().GetResult()
    $stderr = $Owned.StderrTask.GetAwaiter().GetResult()
    [void]$trackedProcesses.Remove($Owned.Process.Id)
    return [pscustomobject]@{
        ExitCode = $Owned.Process.ExitCode
        Stdout = $stdout
        Stderr = $stderr
        Pid = $Owned.Process.Id
    }
}

function Convert-ControlOutput($Completed, [string]$Operation) {
    $lines = @($Completed.Stdout -split "`r?`n" | Where-Object { $_.Length -gt 0 })
    Assert-Equal $lines.Count 1 "$Operation did not emit exactly one JSON object."
    try {
        $body = $lines[0] | ConvertFrom-Json
    } catch {
        throw "$Operation emitted invalid JSON."
    }
    Assert-Equal $body.kind "control_result" "$Operation emitted the wrong result kind."
    Assert-Equal $body.operation $Operation "$Operation output is mislabeled."
    return [pscustomobject]@{
        ExitCode = $Completed.ExitCode
        Body = $body
        Stderr = $Completed.Stderr
        Pid = $Completed.Pid
    }
}

function Invoke-Control(
    [string]$Executable,
    [string]$Operation,
    [string[]]$Arguments,
    [int]$TimeoutSeconds = $ProcessTimeoutSeconds
) {
    $owned = Start-OwnedProcess $Executable $Arguments
    return Convert-ControlOutput (Complete-OwnedProcess $owned $TimeoutSeconds) $Operation
}

function Open-TaskScheduler {
    $script:TaskService = New-Object -ComObject 'Schedule.Service'
    $script:TaskService.Connect()
    $script:TaskFolder = $script:TaskService.GetFolder('\')
}

function Get-ExactTask([string]$TaskName) {
    try {
        return $script:TaskFolder.GetTask($TaskName)
    } catch {
        if ($_.Exception.HResult -in @(-2147024894, -2147024893)) {
            return $null
        }
        throw
    }
}

function Get-TaskSnapshot([string]$TaskName) {
    $task = Get-ExactTask $TaskName
    if ($null -eq $task) {
        return [pscustomobject]@{
            State = 'ABSENT'
            Enabled = $false
            Instances = 0
            EnginePids = @()
            Arguments = $null
            ActionPath = $null
            Source = $null
            XmlDigest = $null
        }
    }
    $instances = $task.GetInstances(0)
    $enginePids = @()
    for ($index = 1; $index -le $instances.Count; $index++) {
        $enginePids += [int]$instances.Item($index).EnginePID
    }
    $definition = $task.Definition
    $action = if ($definition.Actions.Count -eq 1) { $definition.Actions.Item(1) } else { $null }
    $state = switch ([int]$task.State) {
        1 { 'DISABLED' }
        2 { 'QUEUED' }
        3 { 'READY' }
        4 { 'RUNNING' }
        default { 'UNKNOWN' }
    }
    return [pscustomobject]@{
        State = $state
        Enabled = [bool]$task.Enabled
        Instances = [int]$instances.Count
        EnginePids = @($enginePids)
        Arguments = if ($action) { [string]$action.Arguments } else { $null }
        ActionPath = if ($action) { [string]$action.Path } else { $null }
        Source = [string]$definition.RegistrationInfo.Source
        XmlDigest = Get-Sha256String ([string]$task.Xml)
    }
}

function Wait-Until([scriptblock]$Condition, [int]$TimeoutSeconds, [string]$FailureMessage) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $value = & $Condition
        if ($null -ne $value -and $value -ne $false) {
            return $value
        }
        Start-Sleep -Milliseconds 10
    } while ([DateTime]::UtcNow -lt $deadline)
    throw $FailureMessage
}

function Stop-ExactOwnedTask([string]$TaskName) {
    $task = Get-ExactTask $TaskName
    if ($null -ne $task) {
        $task.Stop(0)
    }
}

function Delete-ExactFixtureTask([string]$TaskName, [string]$ExpectedExecutable) {
    $snapshot = Get-TaskSnapshot $TaskName
    if ($snapshot.State -eq 'ABSENT') {
        return
    }
    Assert-Equal ([IO.Path]::GetFullPath($snapshot.ActionPath)) ([IO.Path]::GetFullPath($ExpectedExecutable)) "Refusing to delete an unknown task action."
    $expectedSource = "urn:codex-agent-mesh:daemon:$ownedInstallId"
    Assert-Equal $snapshot.Source $expectedSource "Refusing to delete an unknown task owner."
    Assert-True (($snapshot.Arguments -eq 'daemon --install-slot stable') -or ($snapshot.Arguments -like "*$fixtureTaskMutationMarker*")) "Refusing to delete a task with unknown arguments."
    Assert-True $ownedTaskXmlDigests.Contains($snapshot.XmlDigest) "Refusing to delete task XML not produced and captured by this fixture."
    Stop-ExactOwnedTask $TaskName
    Wait-Until { if ((Get-TaskSnapshot $TaskName).Instances -eq 0) { return $true }; return $false } 10 "Owned task instance did not stop."
    $script:TaskFolder.DeleteTask($TaskName, 0)
    Assert-Equal (Get-TaskSnapshot $TaskName).State 'ABSENT' "Exact fixture task deletion did not converge."
}

function Set-ExactTaskDrift([string]$TaskName) {
    $task = Get-ExactTask $TaskName
    Assert-True ($null -ne $task) "Cannot drift an absent fixture task."
    $definition = $task.Definition
    Assert-Equal $definition.Actions.Count 1 "Fixture task did not have one action."
    $definition.Actions.Item(1).Arguments = "daemon --install-slot stable $fixtureTaskMutationMarker"
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $sddl = "D:P(A;;GA;;;SY)(A;;GA;;;$sid)"
    [void]$script:TaskFolder.RegisterTaskDefinition($TaskName, $definition, 6, $sid, $null, 3, $sddl)
    $snapshot = Get-TaskSnapshot $TaskName
    Assert-True ($snapshot.Arguments -like "*$fixtureTaskMutationMarker*") "Task drift injection was not read back."
    [void]$ownedTaskXmlDigests.Add($snapshot.XmlDigest)
}

function Get-DaemonPid([string]$TaskName, [string]$ExpectedRuntime, [string]$ExpectedDigest) {
    $snapshot = Get-TaskSnapshot $TaskName
    Assert-Equal $snapshot.Instances 1 "The fixture requires exactly one scheduled daemon instance."
    $pidValue = [int]$snapshot.EnginePids[0]
    $process = Get-Process -Id $pidValue -ErrorAction Stop
    Assert-Equal ([IO.Path]::GetFullPath($process.Path)) ([IO.Path]::GetFullPath($ExpectedRuntime)) "Scheduled instance image was not the retained runtime."
    Assert-Equal (Get-FileSha256 $process.Path) $ExpectedDigest "Scheduled instance digest drifted."
    return $pidValue
}

function Test-ProcessAlive([int]$PidValue) {
    return $null -ne (Get-Process -Id $PidValue -ErrorAction SilentlyContinue)
}

function Assert-RetainedAssets($Baseline, [string]$ExpectedState = 'RETAINED') {
    $recordEvidence = Read-InstallRecordEvidence
    Assert-True ($null -ne $recordEvidence) "The retained install record is absent."
    $record = $recordEvidence.Record
    Assert-OwnedRecord $record
    Assert-Equal $record.state $ExpectedState "The retained lifecycle is wrong."
    Assert-Equal $record.consumer_id $Baseline.ConsumerId "The retained consumer identity changed."
    Assert-Equal $record.protected_key.relative_path $Baseline.KeyRelativePath "The retained key path changed."
    Assert-Equal $record.protected_key.sha256 $Baseline.KeyDigest "The retained key digest changed."
    Assert-Equal $record.runtime.relative_path $Baseline.RuntimeRelativePath "The retained runtime path changed."
    Assert-Equal $record.runtime.sha256 $Baseline.RuntimeDigest "The retained runtime digest changed."
    Assert-Equal $record.data_relative_path $Baseline.DataRelativePath "The retained data root changed."
    Assert-True (Test-Path -LiteralPath $Baseline.DatabasePath -PathType Leaf) "The retained SQLite database was deleted."
    Assert-True (Test-Path -LiteralPath $Baseline.BlobRoot -PathType Container) "The retained blob root was deleted."
    Assert-True (Test-Path -LiteralPath $Baseline.KeyPath -PathType Leaf) "The retained endpoint-key envelope was deleted."
    Assert-True (Test-Path -LiteralPath $Baseline.RuntimePath -PathType Leaf) "The retained runtime was deleted."
    Assert-Equal (Get-FileSha256 $Baseline.KeyPath) $Baseline.KeyDigest "The retained endpoint-key envelope changed."
    Assert-Equal (Get-FileSha256 $Baseline.RuntimePath) $Baseline.RuntimeDigest "The retained runtime bytes changed."
    Assert-Equal (Get-TreeDigest $Baseline.BlobRoot) $Baseline.BlobTreeDigest "The retained blob tree changed."
}

function Get-RetentionBaseline($Record) {
    $dataRoot = Join-Path $productRoot $Record.data_relative_path
    $keyPath = Join-Path $productRoot $Record.protected_key.relative_path
    $runtimePathValue = Join-Path $productRoot $Record.runtime.relative_path
    foreach ($path in @($dataRoot, $keyPath, $runtimePathValue)) {
        Assert-True (Test-ExactDescendant $path $productRoot) "Install evidence escaped the exact product root."
    }
    $databasePath = Join-Path $dataRoot 'mesh.sqlite3'
    $blobRoot = Join-Path $dataRoot 'blobs'
    Assert-True (Test-Path -LiteralPath $databasePath -PathType Leaf) "Setup did not create the SQLite database."
    Assert-True (Test-Path -LiteralPath $blobRoot -PathType Container) "Setup did not create the blob root."
    Assert-Equal (Get-FileSha256 $keyPath) $Record.protected_key.sha256 "Endpoint-key envelope evidence disagrees with disk."
    Assert-Equal (Get-FileSha256 $runtimePathValue) $Record.runtime.sha256 "Runtime evidence disagrees with disk."
    return [pscustomobject]@{
        InstallId = [string]$Record.install_id
        ConsumerId = [string]$Record.consumer_id
        KeyRelativePath = [string]$Record.protected_key.relative_path
        KeyDigest = [string]$Record.protected_key.sha256
        RuntimeRelativePath = [string]$Record.runtime.relative_path
        RuntimeDigest = [string]$Record.runtime.sha256
        DataRelativePath = [string]$Record.data_relative_path
        KeyPath = $keyPath
        RuntimePath = $runtimePathValue
        DatabasePath = $databasePath
        BlobRoot = $blobRoot
        BlobTreeDigest = Get-TreeDigest $blobRoot
    }
}

function Invoke-ReconnectingBridges([string]$CacheRuntime, [int]$Count) {
    $clients = @()
    for ($index = 0; $index -lt $Count; $index++) {
        $client = Start-OwnedProcess $CacheRuntime @('bridge-bootstrap', '--stdio', '--install-slot', 'stable') $true
        $client.Process.StandardInput.Close()
        $clients += $client
    }
    foreach ($client in $clients) {
        $completed = Complete-OwnedProcess $client 10
        Assert-Equal $completed.ExitCode 10 "A reconnecting bridge was admitted during removal."
        Assert-True ([string]::IsNullOrWhiteSpace($completed.Stdout)) "A rejected reconnecting bridge polluted stdout."
        Assert-True ($completed.Stderr.Length -le 65536) "A rejected reconnecting bridge exceeded the stderr budget."
    }
}

function Add-TimelinePoint([Diagnostics.Stopwatch]$Clock, [string]$Phase) {
    $recordEvidence = Read-InstallRecordEvidence
    Assert-True ($null -ne $recordEvidence) "Setup did not publish a protected install record."
    $record = $recordEvidence.Record
    $task = Get-TaskSnapshot $ownedTaskName
    $alive = if ($null -ne $daemonPid) { Test-ProcessAlive $daemonPid } else { $false }
    $point = [ordered]@{
        phase = $Phase
        elapsedMs = $Clock.ElapsedMilliseconds
        lifecycle = if ($record) { [string]$record.state } else { 'ABSENT' }
        task = $task.State
        instances = $task.Instances
        daemonAlive = $alive
    }
    $last = if ($timelines.Count -gt 0) { $timelines[$timelines.Count - 1] } else { $null }
    if ($null -eq $last -or $last.lifecycle -ne $point.lifecycle -or $last.task -ne $point.task -or $last.instances -ne $point.instances -or $last.daemonAlive -ne $point.daemonAlive) {
        $timelines.Add([pscustomobject]$point)
    }
}

function Get-PreflightEvidence {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($knownLocalAppData))
    $sessionName = if ($env:SESSIONNAME) { $env:SESSIONNAME } else { 'UNKNOWN' }
    if (-not ('CodexAgentMeshUninstallFixture.NativeJob' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace CodexAgentMeshUninstallFixture {
    public static class NativeJob {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsProcessInJob(
            IntPtr processHandle,
            IntPtr jobHandle,
            [MarshalAs(UnmanagedType.Bool)] out bool result);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(
            IntPtr tokenHandle,
            int tokenInformationClass,
            out int tokenInformation,
            int tokenInformationLength,
            out int returnLength);
    }
}
'@
    }
    $inJob = $false
    $jobQuery = [CodexAgentMeshUninstallFixture.NativeJob]::IsProcessInJob(
        [Diagnostics.Process]::GetCurrentProcess().Handle,
        [IntPtr]::Zero,
        [ref]$inJob
    )
    if (-not $jobQuery) {
        throw "Harness Job Object membership could not be queried."
    }
    $elevationType = 0
    $elevationLength = 0
    $elevationQuery = [CodexAgentMeshUninstallFixture.NativeJob]::GetTokenInformation(
        $identity.Token,
        18,
        [ref]$elevationType,
        4,
        [ref]$elevationLength
    )
    if (-not $elevationQuery -or $elevationLength -ne 4) {
        throw "Token elevation type could not be queried."
    }
    return [ordered]@{
        osVersion = [Environment]::OSVersion.VersionString
        osBuild = [Environment]::OSVersion.Version.Build
        architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        userSid = $identity.User.Value
        sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
        sessionType = $sessionName
        userInteractive = [Environment]::UserInteractive
        elevatedAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        tokenElevationType = switch ($elevationType) { 1 { 'Default' } 2 { 'Full' } 3 { 'Limited' } default { 'Unknown' } }
        filesystem = $drive.DriveFormat
        driveType = $drive.DriveType.ToString()
        harnessInJobObject = $inJob
        localAppDataKnownFolderDigest = Get-Sha256String ([IO.Path]::GetFullPath($knownLocalAppData).ToLowerInvariant())
    }
}

function Remove-ExactFixtureTree([string]$Path, [string]$ExpectedParent, [string]$MarkerPath = '') {
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $parent = [IO.Path]::GetFullPath($ExpectedParent).TrimEnd('\')
    $actualParent = [IO.Directory]::GetParent($full).FullName.TrimEnd('\')
    Assert-Equal $actualParent $parent "Refusing recursive cleanup without exact direct-parent ownership."
    $targetItem = Get-Item -LiteralPath $full -Force
    Assert-True $targetItem.PSIsContainer "Recursive cleanup target is not a directory."
    Assert-True (-not ($targetItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) "Recursive cleanup target is a reparse point."
    $ancestor = $targetItem.Parent
    while ($null -ne $ancestor) {
        Assert-True (-not ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) "Recursive cleanup ancestor is a reparse point."
        $ancestor = $ancestor.Parent
    }
    if ($MarkerPath) {
        Assert-True (Test-Path -LiteralPath $MarkerPath -PathType Leaf) "Fixture cleanup marker is absent."
        $markerItem = Get-Item -LiteralPath $MarkerPath -Force
        Assert-True (-not ($markerItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) "Fixture cleanup marker is a reparse point."
        Assert-Equal $markerItem.DirectoryName $full "Fixture cleanup marker is not a direct child."
        $expectedMarker = ([ordered]@{ fixtureId = $fixtureId } | ConvertTo-Json -Compress)
        Assert-Equal ([IO.File]::ReadAllText($MarkerPath)) $expectedMarker "Fixture cleanup marker bytes disagree."
    }
    $reparse = @(Get-ChildItem -LiteralPath $Path -Force -Recurse | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
    Assert-Equal $reparse.Count 0 "Refusing recursive cleanup through a reparse point."
    Remove-Item -LiteralPath $Path -Recurse -Force
}

$preflightFailures = [Collections.Generic.List[string]]::new()
try {
    $preflight = Get-PreflightEvidence
} catch {
    $preflight = [ordered]@{
        osVersion = [Environment]::OSVersion.VersionString
        osBuild = [Environment]::OSVersion.Version.Build
        architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
        userSid = 'UNAVAILABLE'
        sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
        sessionType = 'UNKNOWN'
        userInteractive = [Environment]::UserInteractive
        elevatedAdministrator = $true
        tokenElevationType = 'Unknown'
        filesystem = 'UNKNOWN'
        driveType = 'UNKNOWN'
        harnessInJobObject = $null
        localAppDataKnownFolderDigest = Get-Sha256String ([IO.Path]::GetFullPath($knownLocalAppData).ToLowerInvariant())
    }
    $preflightFailures.Add('Required Windows identity/session/filesystem evidence could not be collected.')
}
$environmentDigest = Get-Sha256String ($preflight | ConvertTo-Json -Compress)

if (-not $IsWindows) { $preflightFailures.Add('Windows is required.') }
if ($preflight.architecture -ne 'X64') { $preflightFailures.Add('Windows x64 is required.') }
if (-not $preflight.userInteractive -or $preflight.sessionId -eq 0) { $preflightFailures.Add('A logged-in interactive user session is required.') }
if ($preflight.elevatedAdministrator -or $preflight.tokenElevationType -in @('Full', 'Limited')) { $preflightFailures.Add('Run from a non-elevated, non-filtered standard-user token.') }
if ($preflight.filesystem -ne 'NTFS' -or $preflight.driveType -ne 'Fixed') { $preflightFailures.Add('LocalAppData must be on a fixed NTFS volume.') }
if ($productRootExistedBefore) { $preflightFailures.Add('The current profile already has a codex-agent-mesh product root; exact fixture ownership cannot be proven.') }

if (-not $RuntimePath) {
    foreach ($candidate in @(
        (Join-Path $repositoryRoot 'target\debug\mesh-daemon.exe'),
        (Join-Path $repositoryRoot 'target\release\mesh-daemon.exe')
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $RuntimePath = $candidate
            break
        }
    }
}
if (-not $RuntimePath -or -not (Test-Path -LiteralPath $RuntimePath -PathType Leaf)) {
    $preflightFailures.Add('A built mesh-daemon.exe fixture is required; pass -RuntimePath or build the debug runtime.')
} else {
    $RuntimePath = (Resolve-Path -LiteralPath $RuntimePath).Path
    if ((Get-AuthenticodeSignature -LiteralPath $RuntimePath).Status -ne 'NotSigned') {
        $preflightFailures.Add('This fixture requires an explicitly unsigned development runtime, not an official-signing simulation.')
    }
}

try {
    Open-TaskScheduler
} catch {
    $preflightFailures.Add('Task Scheduler 2.0 COM is unavailable to the current user.')
}

if ($preflightFailures.Count -gt 0) {
    $notRun = [ordered]@{
        kind = 'daemon_uninstall_acceptance'
        outcome = 'NOT_RUN'
        strictFixtureRequired = [bool]$RequireFixture
        reasons = @($preflightFailures)
        evidence = $preflight
        environmentDigest = $environmentDigest
        releaseBlockers = @('Full M3 purge/reinstall identity regeneration must run on a dedicated clean standard-user NTFS profile fixture.')
    }
    $notRun | ConvertTo-Json -Depth 8
    if ($RequireFixture) { exit 1 }
    exit 0
}

try {
    [void](New-Item -ItemType Directory -Path $bundleRoot, $callerRoot, $spoofedLocalAppData -Force)
    [IO.File]::WriteAllText($fixtureMarkerPath, ([ordered]@{ fixtureId = $fixtureId } | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
    $cacheRuntime = Join-Path $bundleRoot 'mesh-daemon.exe'
    Copy-Item -LiteralPath $RuntimePath -Destination $cacheRuntime
    $runtimeDigest = Get-FileSha256 $cacheRuntime

    $setupStarted = $true
    $setup = Invoke-Control $cacheRuntime 'setup' @('setup', '--install-slot', 'stable')
    Assert-Equal $setup.ExitCode 0 "Development setup failed."
    Assert-True $setup.Body.ok "Development setup did not report success."
    Assert-Equal $setup.Body.lifecycle 'ACTIVE' "Setup did not publish ACTIVE last."
    $recordEvidence = Read-InstallRecordEvidence
    Assert-True ($null -ne $recordEvidence) "Setup did not publish a protected install record."
    $record = $recordEvidence.Record
    $ownedInstallId = [string]$record.install_id
    Assert-OwnedRecord $record
    Assert-Equal $record.state 'ACTIVE' "Setup record is not ACTIVE."
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $spoofedLocalAppData 'codex-agent-mesh'))) "Setup trusted spoofed LOCALAPPDATA instead of the Known Folder root."
    $ownedTaskName = ([string]$record.scheduled_task.task_path).TrimStart('\')
    Assert-True ($ownedTaskName.Length -gt 0) "Setup did not record an exact task path."
    $baseline = Get-RetentionBaseline $record
    $stableRuntimePath = $baseline.RuntimePath
    $initialTask = Get-TaskSnapshot $ownedTaskName
    Assert-Equal $initialTask.State 'READY' "Fresh setup task is not stopped/ready."
    Assert-Equal $initialTask.Arguments 'daemon --install-slot stable' "Fresh setup task arguments drifted."
    Assert-Equal $baseline.RuntimeDigest $runtimeDigest "Setup retained bytes differ from this run's cache runtime."
    $ownedConsumerId = [string]$record.consumer_id
    $ownedTaskDefinitionDigest = [string]$record.scheduled_task.definition_sha256
    $ownedInitialRecordDigest = $recordEvidence.Sha256
    Assert-Equal (Get-FileSha256 $recordPath) $ownedInitialRecordDigest "Install record changed while fixture ownership was being bound."
    [void]$ownedTaskXmlDigests.Add($initialTask.XmlDigest)
    $ownershipBound = $true
    $checks.Add('setup-active-stopped-task')

    # Prime the audited daemon lock file, then stop the exact scheduled
    # instance. This leaves a genuine stopped/READY task without inventing a
    # fixture-only installation root.
    $start = Invoke-Control $stableRuntimePath 'start' @('start', '--install-slot', 'stable')
    Assert-Equal $start.ExitCode 0 "Daemon start for stopped-task preparation failed."
    $daemonPid = Get-DaemonPid $ownedTaskName $stableRuntimePath $runtimeDigest
    Stop-ExactOwnedTask $ownedTaskName
    Wait-Until { if (-not (Test-ProcessAlive $daemonPid)) { return $true }; return $false } 10 "Exact scheduled daemon did not stop."
    Wait-Until { if ((Get-TaskSnapshot $ownedTaskName).State -eq 'READY') { return $true }; return $false } 10 "Task did not return to READY."
    $daemonLockPath = Join-Path (Join-Path $productRoot $record.product_relative_path) 'run\daemon.lock'
    Assert-True (Test-Path -LiteralPath $daemonLockPath -PathType Leaf) "The audited daemon lock file is absent."
    $daemonLockBlocker = [IO.File]::Open($daemonLockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)

    $stoppedRemove = Start-OwnedProcess $stableRuntimePath @('remove', '--install-slot', 'stable')
    Wait-Until {
        $candidate = Read-InstallRecord
        if ($candidate -and $candidate.state -eq 'REMOVING') { return $candidate }
        return $null
    } 5 "Stopped-task removal never published REMOVING."
    Wait-Until { if ((Get-TaskSnapshot $ownedTaskName).State -eq 'DISABLED') { return $true }; return $false } 5 "Stopped-task removal did not disable the exact task."
    [void]$ownedTaskXmlDigests.Add((Get-TaskSnapshot $ownedTaskName).XmlDigest)
    $removingStart = Invoke-Control $cacheRuntime 'start' @('start', '--install-slot', 'stable') 10
    Assert-Equal $removingStart.ExitCode 10 "Start during REMOVING returned the wrong exit."
    Assert-Equal $removingStart.Body.error.code 'SETUP_REMOVING' "Start did not expose the exact REMOVING fence."
    Invoke-ReconnectingBridges $cacheRuntime $ReconnectClients
    Assert-Equal (Get-TaskSnapshot $ownedTaskName).State 'DISABLED' "Reconnect traffic re-enabled or started the task."
    Stop-OwnedProcess $stoppedRemove
    [void](Complete-OwnedProcess $stoppedRemove 5)
    $daemonLockBlocker.Dispose()
    $daemonLockBlocker = $null
    Assert-Equal (Read-InstallRecord).state 'REMOVING' "Killed remover lost the persistent fence."
    $stoppedResume = Invoke-Control $stableRuntimePath 'remove' @('remove', '--install-slot', 'stable')
    Assert-Equal $stoppedResume.ExitCode 0 "Stopped-task removal did not converge after restart."
    Assert-Equal $stoppedResume.Body.lifecycle 'RETAINED' "Stopped-task removal did not reach RETAINED."
    Assert-Equal (Get-TaskSnapshot $ownedTaskName).State 'ABSENT' "Stopped-task removal did not prove task absence."
    Assert-RetainedAssets $baseline
    $checks.Add('stopped-disable-kill-restart-absence-retention')

    $reinstall = Invoke-Control $cacheRuntime 'setup' @('setup', '--install-slot', 'stable')
    Assert-Equal $reinstall.ExitCode 0 "Retained reinstall failed."
    $reinstalledRecord = Read-InstallRecord
    Assert-OwnedRecord $reinstalledRecord
    Assert-Equal $reinstalledRecord.state 'ACTIVE' "Retained reinstall did not return ACTIVE."
    Assert-Equal $reinstalledRecord.protected_key.sha256 $baseline.KeyDigest "Retained reinstall changed the endpoint-key envelope."
    Assert-Equal $reinstalledRecord.runtime.sha256 $baseline.RuntimeDigest "Retained reinstall changed runtime identity."
    $checks.Add('retained-reinstall-same-identity')

    # A live authenticated bridge holds one server connection in a bounded
    # read. That prevents graceful daemon lock release within five seconds and
    # forces the real Task Scheduler Stop fallback before exact deletion.
    $start = Invoke-Control $stableRuntimePath 'start' @('start', '--install-slot', 'stable')
    Assert-Equal $start.ExitCode 0 "Running-task daemon start failed."
    $daemonPid = Get-DaemonPid $ownedTaskName $stableRuntimePath $runtimeDigest
    $blockingBridge = Start-OwnedProcess $stableRuntimePath @('bridge', '--stdio', '--install-slot', 'stable') $true
    Start-Sleep -Milliseconds 500
    Assert-True (-not $blockingBridge.Process.HasExited) "Authenticated blocking bridge did not stay connected."

    $clock = [Diagnostics.Stopwatch]::StartNew()
    $runningRemove = Start-OwnedProcess $stableRuntimePath @('remove', '--install-slot', 'stable')
    Wait-Until {
        Add-TimelinePoint $clock 'running-remove'
        $candidate = Read-InstallRecord
        if ($candidate -and $candidate.state -eq 'REMOVING') { return $candidate }
        return $null
    } 5 "Running-task removal never published REMOVING."
    # Block only the final record replacement. The remover already owns the
    # install.lock fence, so task shutdown/delete can continue while RETAINED
    # publication is forced to fail after read-back absence.
    $recordBlocker = [IO.File]::Open($recordPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    Wait-Until {
        Add-TimelinePoint $clock 'running-remove'
        if ((Get-TaskSnapshot $ownedTaskName).State -eq 'DISABLED') { return $true }
        return $false
    } 5 "Running-task removal did not disable the task."
    [void]$ownedTaskXmlDigests.Add((Get-TaskSnapshot $ownedTaskName).XmlDigest)
    Invoke-ReconnectingBridges $cacheRuntime $ReconnectClients
    $removingStart = Invoke-Control $cacheRuntime 'start' @('start', '--install-slot', 'stable') 10
    Assert-Equal $removingStart.Body.error.code 'SETUP_REMOVING' "Running removal did not fence new starts."
    Wait-Until {
        Add-TimelinePoint $clock 'running-remove'
        if ((Get-TaskSnapshot $ownedTaskName).State -eq 'ABSENT') { return $true }
        return $false
    } 15 "Running-task removal did not stop/delete/read back absence."
    Add-TimelinePoint $clock 'task-absent-record-blocked'
    Assert-True ($clock.ElapsedMilliseconds -ge 4500) "The blocked bridge did not exercise the five-second stop fallback."
    Assert-True (-not (Test-ProcessAlive $daemonPid)) "The scheduled daemon survived Task Scheduler Stop."
    $failedFinalCas = Convert-ControlOutput (Complete-OwnedProcess $runningRemove 10) 'remove'
    Assert-Equal $failedFinalCas.ExitCode 12 "Injected final record publication failure returned the wrong exit."
    Assert-Equal $failedFinalCas.Body.error.code 'STORAGE_UNAVAILABLE' "Final record publication failure was not actionable."
    Assert-Equal (Read-InstallRecord).state 'REMOVING' "Failed final publication cleared the removal fence."
    $recordBlocker.Dispose()
    $recordBlocker = $null
    if (-not $blockingBridge.Process.HasExited) {
        $blockingBridge.Process.StandardInput.Close()
    }
    [void](Complete-OwnedProcess $blockingBridge 10)
    $blockingBridge = $null
    $runningResume = Invoke-Control $stableRuntimePath 'remove' @('remove', '--install-slot', 'stable')
    Assert-Equal $runningResume.ExitCode 0 "Running-task removal did not converge after final-checkpoint restart."
    Assert-Equal $runningResume.Body.lifecycle 'RETAINED' "Running-task removal did not publish RETAINED last."
    Add-TimelinePoint $clock 'restart-retained'
    $clock.Stop()
    Assert-RetainedAssets $baseline
    $checks.Add('running-grace-stop-delete-absence-restart-retention')

    # Recreate the exact installation and then alter its one known task. The
    # product must preserve the changed/colliding object and return a manual,
    # actionable drift result while keeping REMOVING as the admission fence.
    $reinstall = Invoke-Control $cacheRuntime 'setup' @('setup', '--install-slot', 'stable')
    Assert-Equal $reinstall.ExitCode 0 "Second retained reinstall failed."
    Set-ExactTaskDrift $ownedTaskName
    $driftXmlDigest = (Get-TaskSnapshot $ownedTaskName).XmlDigest
    $driftRemove = Invoke-Control $stableRuntimePath 'remove' @('remove', '--install-slot', 'stable')
    Assert-Equal $driftRemove.ExitCode 10 "Drifted task removal returned the wrong exit."
    Assert-Equal $driftRemove.Body.error.code 'SETUP_DRIFTED' "Drifted task removal was not actionable."
    $driftSnapshot = Get-TaskSnapshot $ownedTaskName
    Assert-True ($driftSnapshot.State -ne 'ABSENT') "Product removal deleted a changed/colliding task."
    Assert-Equal $driftSnapshot.XmlDigest $driftXmlDigest "Product removal rewrote the changed/colliding task."
    Assert-Equal (Read-InstallRecord).state 'REMOVING' "Drift refusal cleared the removal fence."
    $collisionDefinition = (Get-ExactTask $ownedTaskName).Definition
    $driftStart = Invoke-Control $cacheRuntime 'start' @('start', '--install-slot', 'stable')
    Assert-Equal $driftStart.Body.error.code 'SETUP_REMOVING' "Drifted REMOVING state admitted a start."
    $checks.Add('changed-task-preserved-actionable-drift')

    # The fixture, not product uninstall, now removes only its exact intentionally
    # altered task after checking image, owner marker, and unique drift argument.
    Delete-ExactFixtureTask $ownedTaskName $stableRuntimePath
    $finalRemove = Invoke-Control $stableRuntimePath 'remove' @('remove', '--install-slot', 'stable')
    Assert-Equal $finalRemove.ExitCode 0 "Fixture cleanup removal did not converge."
    Assert-RetainedAssets $baseline

    # Re-register the fixture's already-verified altered definition at the same
    # exact path after RETAINED. This is a true name collision/recreation, not a
    # prefix search. Product remove must preserve it and remain RETAINED.
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $sddl = "D:P(A;;GA;;;SY)(A;;GA;;;$sid)"
    [void]$script:TaskFolder.RegisterTaskDefinition($ownedTaskName, $collisionDefinition, 2, $sid, $null, 3, $sddl)
    $collisionBefore = Get-TaskSnapshot $ownedTaskName
    Assert-True ($collisionBefore.Arguments -like "*$fixtureTaskMutationMarker*") "Exact collision fixture was not read back."
    [void]$ownedTaskXmlDigests.Add($collisionBefore.XmlDigest)
    $collisionRemove = Invoke-Control $stableRuntimePath 'remove' @('remove', '--install-slot', 'stable')
    Assert-Equal $collisionRemove.ExitCode 10 "Colliding retained task returned the wrong exit."
    Assert-Equal $collisionRemove.Body.error.code 'SETUP_DRIFTED' "Colliding retained task was not actionable drift."
    $collisionAfter = Get-TaskSnapshot $ownedTaskName
    Assert-Equal $collisionAfter.XmlDigest $collisionBefore.XmlDigest "Product removal rewrote or deleted the colliding task."
    Assert-Equal (Read-InstallRecord).state 'RETAINED' "Collision refusal mutated RETAINED lifecycle."
    Delete-ExactFixtureTask $ownedTaskName $stableRuntimePath
    $collisionResume = Invoke-Control $stableRuntimePath 'remove' @('remove', '--install-slot', 'stable')
    Assert-Equal $collisionResume.ExitCode 0 "Collision cleanup did not remain idempotently RETAINED."
    $checks.Add('colliding-task-preserved-actionable-drift')

    # Explicit purge must run from an external controller. The retained stable
    # image lives inside the target tree and must refuse before any mutation.
    $stablePurgeRefusal = Invoke-Control $stableRuntimePath 'remove' @('remove', '--install-slot', 'stable', '--purge-data') 30
    Assert-Equal $stablePurgeRefusal.ExitCode 10 "In-tree purge returned the wrong exit."
    Assert-Equal $stablePurgeRefusal.Body.error.code 'PURGE_EXTERNAL_CONTROLLER_REQUIRED' "In-tree purge was not refused with the frozen controller code."
    Assert-Equal (Read-InstallRecord).state 'RETAINED' "In-tree purge refusal mutated the lifecycle."
    Assert-Equal (Get-TaskSnapshot $ownedTaskName).State 'ABSENT' "In-tree purge refusal touched the task."
    $checks.Add('purge-external-controller-required')

    # Deterministic drain checkpoint: a no-share foreign holder of the in-tree
    # startup.lock must yield a bounded PURGE_BUSY after the durable PURGING
    # fence, leaving PURGING+Source for an exact command replay.
    $startupLockPath = Join-Path $productRoot "installs\$ownedInstallId\run\startup.lock"
    Assert-True (Test-Path -LiteralPath $startupLockPath -PathType Leaf) "The fixture requires the audited startup.lock file."
    $purgeStartupLockBlocker = [IO.File]::Open($startupLockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $busyPurge = Invoke-Control $cacheRuntime 'remove' @('remove', '--install-slot', 'stable', '--purge-data') 30
    } finally {
        $purgeStartupLockBlocker.Dispose()
        $purgeStartupLockBlocker = $null
    }
    Assert-Equal $busyPurge.ExitCode 11 "Blocked purge drain returned the wrong exit."
    Assert-Equal $busyPurge.Body.error.code 'PURGE_BUSY' "Blocked purge drain was not bounded and actionable."
    Assert-Equal (Read-InstallRecord).state 'PURGING' "Blocked purge drain did not publish the durable PURGING fence."
    Assert-True (Test-Path -LiteralPath (Join-Path $productRoot "installs\$ownedInstallId") -PathType Container) "PURGING+Source checkpoint lost the source tree."
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $productRoot "purge\$ownedInstallId"))) "PURGING+Source checkpoint staged a tombstone prematurely."
    $checks.Add('purge-startup-drain-checkpoint')

    # Replaying the exact command converges from PURGING+Source to record
    # absence: identity-bearing trees, key, runtime, database, and blobs all
    # disappear while only the structural lock paths may remain.
    $purge = Invoke-Control $cacheRuntime 'remove' @('remove', '--install-slot', 'stable', '--purge-data') 60
    Assert-Equal $purge.ExitCode 0 "Exact purge did not converge."
    Assert-Equal $purge.Body.lifecycle 'ABSENT' "Purge did not report lifecycle absence."
    Assert-Equal $purge.Body.purged_data $true "Purge did not report purged data."
    Assert-Equal $purge.Body.retained_data $false "Purge mislabeled retained data."
    Assert-True (-not (Test-Path -LiteralPath $recordPath)) "Record-last deletion left the install record."
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $productRoot "installs\$ownedInstallId"))) "Purge left the install source tree."
    Assert-True (-not (Test-Path -LiteralPath (Join-Path $productRoot "purge\$ownedInstallId"))) "Purge left the deterministic tombstone."
    Assert-True (-not (Test-Path -LiteralPath $baseline.DatabasePath)) "Purge left the SQLite database."
    Assert-True (-not (Test-Path -LiteralPath $baseline.BlobRoot)) "Purge left the blob root."
    Assert-True (-not (Test-Path -LiteralPath $baseline.KeyPath)) "Purge left the endpoint-key envelope."
    Assert-True (-not (Test-Path -LiteralPath $baseline.RuntimePath)) "Purge left the retained runtime."
    Assert-Equal (Get-TaskSnapshot $ownedTaskName).State 'ABSENT' "Purge left the owned scheduled task."
    $checks.Add('purge-record-last-absence')

    # Clean absence is idempotent and never returns deleted identity.
    $secondPurge = Invoke-Control $cacheRuntime 'remove' @('remove', '--install-slot', 'stable', '--purge-data') 30
    Assert-Equal $secondPurge.ExitCode 0 "Idempotent purge returned the wrong exit."
    Assert-Equal $secondPurge.Body.already_absent $true "Idempotent purge did not report already_absent."
    Assert-True ($null -eq $secondPurge.Body.PSObject.Properties['install_id']) "Idempotent purge leaked a deleted identity."
    Assert-True ($null -eq $secondPurge.Body.PSObject.Properties['consumer_id']) "Idempotent purge leaked a deleted consumer identity."
    $checks.Add('purge-already-absent-idempotent')

    # Reinstall regenerates every stable identity while the old ones stay dead.
    $purgedReinstall = Invoke-Control $cacheRuntime 'setup' @('setup', '--install-slot', 'stable')
    Assert-Equal $purgedReinstall.ExitCode 0 "Post-purge reinstall failed."
    $regenerated = Read-InstallRecord
    Assert-True ($null -ne $regenerated) "Post-purge reinstall did not publish a record."
    Assert-Equal $regenerated.state 'ACTIVE' "Post-purge reinstall did not reach ACTIVE."
    Assert-True ($regenerated.install_id -ne $ownedInstallId) "Reinstall reused the purged install identity."
    Assert-True ($regenerated.consumer_id -ne $ownedConsumerId) "Reinstall reused the purged consumer identity."
    Assert-True ($regenerated.protected_key.sha256 -ne $baseline.KeyDigest) "Reinstall reused the purged endpoint-key envelope."
    Assert-True ($regenerated.scheduled_task.task_path -ne "\$ownedTaskName") "Reinstall reused the purged task name."
    Assert-Equal (Get-TaskSnapshot $ownedTaskName).State 'ABSENT' "The purged task name became reachable again."
    Assert-True (-not (Test-Path -LiteralPath $baseline.KeyPath)) "The purged key envelope path became reachable again."
    Assert-True (-not (Test-Path -LiteralPath $baseline.DatabasePath)) "The purged database path became reachable again."
    $checks.Add('purge-regenerated-identity')

    # Return the regenerated install to the fixture's retained shape so the
    # ownership-checked cleanup can remove the tree and its new exact task.
    $regeneratedRemove = Invoke-Control $cacheRuntime 'remove' @('remove', '--install-slot', 'stable') 30
    Assert-Equal $regeneratedRemove.ExitCode 0 "Post-purge regenerated removal did not converge."
    Assert-Equal $regeneratedRemove.Body.lifecycle 'RETAINED' "Post-purge regenerated removal did not retain."
    Assert-Equal (Get-TaskSnapshot ([string]$regenerated.scheduled_task.task_path).TrimStart('\')).State 'ABSENT' "Regenerated task survived removal."
} catch {
    $failure = $_
} finally {
    foreach ($handleName in @('recordBlocker', 'daemonLockBlocker', 'purgeStartupLockBlocker')) {
        $handle = Get-Variable -Name $handleName -ValueOnly -ErrorAction SilentlyContinue
        if ($null -ne $handle) {
            try { $handle.Dispose() } catch { }
            Set-Variable -Name $handleName -Value $null
        }
    }
    if ($null -ne $blockingBridge) {
        try { $blockingBridge.Process.StandardInput.Close() } catch { }
    }
    foreach ($owned in @($trackedProcesses.Values)) {
        try { Stop-OwnedProcess $owned } catch { $cleanup.retainedSideEffects += 'tracked-process-cleanup-failed' }
    }
    $trackedProcesses.Clear()

    if ($setupStarted -and (Test-Path -LiteralPath $productRoot)) {
        try {
            if (-not $ownershipBound) {
                $cleanup.retainedSideEffects += 'unbound-product-state-preserved'
                $cleanup.productRootRemoved = $false
                throw "Fixture ownership was not bound; preserving product state."
            }
            $cleanupRecord = Read-InstallRecord
            if ($null -ne $cleanupRecord) {
                if ($checks.Contains('purge-regenerated-identity') -and $cleanupRecord.install_id -ne $ownedInstallId) {
                    Assert-True ($cleanupRecord.install_id -match '^[0-9a-f]{32}$') "The regenerated install identity is malformed."
                    Assert-True ($cleanupRecord.consumer_id -match '^[0-9a-f]{32}$') "The regenerated consumer identity is malformed."
                } else {
                    Assert-OwnedStableTuple $cleanupRecord
                }
            } else {
                Assert-True $checks.Contains('purge-record-last-absence') "The install record is absent without purge evidence."
            }
            if ($ownedTaskName) {
                $snapshot = Get-TaskSnapshot $ownedTaskName
                if ($snapshot.State -ne 'ABSENT') {
                    if ($stableRuntimePath -and (Test-Path -LiteralPath $stableRuntimePath -PathType Leaf)) {
                        try { [void](Invoke-Control $stableRuntimePath 'remove' @('remove', '--install-slot', 'stable') 15) } catch { }
                    }
                    $snapshot = Get-TaskSnapshot $ownedTaskName
                    if ($snapshot.State -ne 'ABSENT') {
                        Delete-ExactFixtureTask $ownedTaskName $stableRuntimePath
                    }
                }
                $cleanup.taskAbsent = ((Get-TaskSnapshot $ownedTaskName).State -eq 'ABSENT')
            }
            if ($cleanup.taskAbsent -ne $false) {
                $exactExpectedRoot = [IO.Path]::GetFullPath((Join-Path $knownLocalAppData 'codex-agent-mesh')).TrimEnd('\')
                Assert-Equal ([IO.Path]::GetFullPath($productRoot).TrimEnd('\')) $exactExpectedRoot "Product cleanup target changed."
                Assert-OwnedStableTuple (Read-InstallRecord)
                Remove-ExactFixtureTree $productRoot $knownLocalAppData
                $cleanup.productRootRemoved = -not (Test-Path -LiteralPath $productRoot)
            }
        } catch {
            $cleanup.retainedSideEffects += 'exact-product-cleanup-failed'
            $cleanup.productRootRemoved = $false
        }
    } else {
        $cleanup.productRootRemoved = -not (Test-Path -LiteralPath $productRoot)
    }

    try {
        if (Test-Path -LiteralPath $fixtureRoot) {
            Remove-ExactFixtureTree $fixtureRoot ([IO.Path]::GetTempPath()) $fixtureMarkerPath
        }
        $cleanup.temporaryRootRemoved = -not (Test-Path -LiteralPath $fixtureRoot)
    } catch {
        $cleanup.retainedSideEffects += 'temporary-fixture-cleanup-failed'
        $cleanup.temporaryRootRemoved = $false
    }
}

$taskDefinitionDigest = $null
$taskXmlDigest = $null
if ($null -ne $baseline) {
    $finalRecord = if (Test-Path -LiteralPath $recordPath) { Read-InstallRecord } else { $null }
    $taskDefinitionDigest = if ($finalRecord -and $finalRecord.scheduled_task) { [string]$finalRecord.scheduled_task.definition_sha256 } else { [string]$record.scheduled_task.definition_sha256 }
    $taskXmlDigest = $initialTask.XmlDigest
}

$reportOutcome = if ($null -ne $failure) { 'FAIL' } elseif ($cleanup.retainedSideEffects.Count -gt 0) { 'FAIL' } elseif ($checks.Contains('purge-regenerated-identity')) { 'PASS' } else { 'PASS_WITH_RELEASE_BLOCKER' }

$report = [ordered]@{
    kind = 'daemon_uninstall_acceptance'
    outcome = $reportOutcome
    evidence = [ordered]@{
        osVersion = $preflight.osVersion
        osBuild = $preflight.osBuild
        architecture = $preflight.architecture
        userSid = $preflight.userSid
        sessionId = $preflight.sessionId
        sessionType = $preflight.sessionType
        tokenElevationType = $preflight.tokenElevationType
        filesystem = $preflight.filesystem
        driveType = $preflight.driveType
        environmentDigest = $environmentDigest
        runtimeSha256 = $runtimeDigest
        initialInstallRecordSha256 = $ownedInitialRecordDigest
        taskDefinitionSha256 = $taskDefinitionDigest
        taskXmlSha256 = $taskXmlDigest
        harnessInJobObject = $preflight.harnessInJobObject
    }
    checks = @($checks)
    timeline = @($timelines)
    purge = [ordered]@{
        status = if ($checks.Contains('purge-regenerated-identity')) { 'COMPLETE_IDENTITY_REGENERATED' } elseif ($checks.Contains('purge-record-last-absence')) { 'TREE_AND_RECORD_REMOVED' } elseif ($checks.Contains('purge-startup-drain-checkpoint')) { 'BOUNDED_CHECKPOINT_ONLY' } else { 'NOT_TESTED' }
        externalControllerRefusalTested = $checks.Contains('purge-external-controller-required')
        startupDrainCheckpointTested = $checks.Contains('purge-startup-drain-checkpoint')
        recordLastAbsenceTested = $checks.Contains('purge-record-last-absence')
        idempotentAbsenceTested = $checks.Contains('purge-already-absent-idempotent')
        regeneratedIdentityTested = $checks.Contains('purge-regenerated-identity')
    }
    cleanup = $cleanup
    failure = if ($failure) { [ordered]@{ type = $failure.Exception.GetType().Name; messageDigest = Get-Sha256String $failure.Exception.Message } } else { $null }
    releaseBlockers = if ($reportOutcome -eq 'PASS') { @() } else { @('Exact-tree purge, crash-convergence, and identity regeneration require a dedicated clean standard-user NTFS profile fixture.') }
}
$report | ConvertTo-Json -Depth 10

if ($report.outcome -eq 'FAIL') {
    exit 1
}
exit 0
