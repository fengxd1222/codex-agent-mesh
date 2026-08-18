Set-StrictMode -Version Latest

if (-not ('BoundedStreamDrain' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'BoundedStreamDrain.cs') }

function Get-MeshFixtureHostEvidence {
    if (-not $IsWindows) {
        return [pscustomobject]@{
            is_windows = $false; os_version = [Environment]::OSVersion.VersionString; os_build = $null
            process_architecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
            user_sid = $null; session_id = $null; user_interactive = [Environment]::UserInteractive
            is_system = $false; is_elevated = $false; elevation_type = 'UNAVAILABLE'
            local_data_filesystem = $null; harness_in_job = $null
        }
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $process = [Diagnostics.Process]::GetCurrentProcess()
    $localData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($localData))
    [pscustomobject]@{
        is_windows = $IsWindows
        os_version = [Environment]::OSVersion.VersionString
        os_build = [Environment]::OSVersion.Version.Build
        process_architecture = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
        user_sid = $identity.User.Value
        session_id = $process.SessionId
        user_interactive = [Environment]::UserInteractive
        is_system = $identity.IsSystem
        is_elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        elevation_type = [MeshFixtureNative]::CurrentTokenElevationType()
        local_data_filesystem = $drive.DriveFormat
        harness_in_job = [MeshFixtureNative]::IsCurrentProcessInAnyJob()
    }
}

function Get-MeshFixtureCapability {
    param([Parameter(Mandatory)]$HostEvidence)
    if (-not $HostEvidence.is_windows) { return 'WINDOWS_REQUIRED' }
    if (-not $HostEvidence.user_interactive -or $HostEvidence.session_id -eq 0) { return 'INTERACTIVE_TOKEN_REQUIRED' }
    if ($HostEvidence.is_system) { return 'CURRENT_USER_TOKEN_REQUIRED' }
    if ($HostEvidence.is_elevated -or $HostEvidence.elevation_type -ne 'Default') { return 'UNELEVATED_STANDARD_USER_REQUIRED' }
    if ($HostEvidence.local_data_filesystem -ne 'NTFS') { return 'LOCAL_NTFS_REQUIRED' }
    return $null
}

function Get-MeshRuntimePath {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [string]$RuntimePath,
        [switch]$SkipBuild
    )
    if ($RuntimePath) {
        $resolved = (Resolve-Path -LiteralPath $RuntimePath -ErrorAction Stop).Path
    } else {
        $resolved = Join-Path $RepositoryRoot 'target\debug\mesh-daemon.exe'
        if (-not $SkipBuild) {
            & cargo build -p mesh-daemon --features unsigned-development --manifest-path (Join-Path $RepositoryRoot 'Cargo.toml')
            if ($LASTEXITCODE -ne 0) { throw 'mesh-daemon development build failed' }
        }
        $resolved = (Resolve-Path -LiteralPath $resolved -ErrorAction Stop).Path
    }
    if ([IO.Path]::GetExtension($resolved) -ne '.exe') { throw 'runtime fixture must be a Windows executable' }
    return $resolved
}

function Assert-MeshFixturePathHasNoReparsePoint {
    param([Parameter(Mandatory)][string]$Path)
    $cursor = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
    for (;;) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'fixture ownership path contains a reparse point'
        }
        $pathRoot = [IO.Path]::GetPathRoot($cursor).TrimEnd([IO.Path]::DirectorySeparatorChar)
        if ($cursor.TrimEnd([IO.Path]::DirectorySeparatorChar).Equals($pathRoot,[StringComparison]::OrdinalIgnoreCase)) { return }
        $cursor = [IO.Path]::GetDirectoryName($cursor).TrimEnd([IO.Path]::DirectorySeparatorChar)
    }
}

function Assert-MeshFixtureTreeHasNoReparsePoint {
    param([Parameter(Mandatory)][string]$Root)
    $paths = [Collections.Generic.Queue[string]]::new()
    $depths = [Collections.Generic.Queue[int]]::new()
    $paths.Enqueue($Root)
    $depths.Enqueue(0)
    $entryCount = 0
    while ($paths.Count -gt 0) {
        $directory = $paths.Dequeue()
        $depth = $depths.Dequeue()
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $entryCount++
            if ($entryCount -gt 4096) { throw 'fixture cleanup tree exceeds its entry bound' }
            $attributes = [IO.File]::GetAttributes($entry)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'fixture cleanup tree contains a descendant reparse point'
            }
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                if ($depth -ge 32) { throw 'fixture cleanup tree exceeds its depth bound' }
                $paths.Enqueue($entry)
                $depths.Enqueue($depth+1)
            }
        }
    }
}

function New-MeshFixtureLayout {
    param(
        [Parameter(Mandatory)][string]$SourceRuntime,
        [Parameter(Mandatory)][string]$RunId
    )
    if ($RunId -notmatch '\A(?:scheduled|job)-[0-9a-f]{32}\z') { throw 'fixture run identity is invalid' }
    $temporary = (Resolve-Path -LiteralPath ([IO.Path]::GetTempPath()) -ErrorAction Stop).ProviderPath.TrimEnd([IO.Path]::DirectorySeparatorChar)
    Assert-MeshFixturePathHasNoReparsePoint -Path $temporary
    $rootId = [Guid]::NewGuid().ToString('N')
    $root = Join-Path $temporary "$rootId Ω fixture space"
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    $markerPath = Join-Path $root '.codex-agent-mesh-fixture-owner'
    $markerContents = "codex-agent-mesh-live-fixture-v1`nrun_id=$RunId`nroot_id=$rootId`n"
    $layout = [pscustomobject]@{
        root = $root; root_id = $rootId; run_id = $RunId
        runtime = $null; caller = $null; marker_path = $markerPath
    }
    try {
        $markerBytes = [Text.UTF8Encoding]::new($false).GetBytes($markerContents)
        $marker = [IO.File]::Open($markerPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $marker.Write($markerBytes,0,$markerBytes.Length); $marker.Flush($true) } finally { $marker.Dispose() }
        $cache = Join-Path $root 'plugin cache with spaces\bin\windows-x64'
        $caller = Join-Path $root 'arbitrary caller cwd 雪'
        New-Item -ItemType Directory -Path $cache,$caller -Force | Out-Null
        $runtime = Join-Path $cache 'mesh-daemon.exe'
        Copy-Item -LiteralPath $SourceRuntime -Destination $runtime
        $layout.runtime = $runtime
        $layout.caller = $caller
        return $layout
    } catch {
        if (Test-Path -LiteralPath $markerPath -PathType Leaf) {
            try { Remove-MeshFixtureLayout -Layout $layout } catch {}
        } else {
            try { [IO.Directory]::Delete($root,$false) } catch {}
        }
        throw
    }
}

function Remove-MeshFixtureLayout {
    param([Parameter(Mandatory)]$Layout)
    $resolved = (Resolve-Path -LiteralPath ([string]$Layout.root) -ErrorAction Stop).ProviderPath.TrimEnd([IO.Path]::DirectorySeparatorChar)
    $temporary = (Resolve-Path -LiteralPath ([IO.Path]::GetTempPath()) -ErrorAction Stop).ProviderPath.TrimEnd([IO.Path]::DirectorySeparatorChar)
    $parent = [IO.Path]::GetDirectoryName($resolved).TrimEnd([IO.Path]::DirectorySeparatorChar)
    if (-not $parent.Equals($temporary,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'fixture cleanup target escaped the owned temporary root'
    }
    $rootId = [string]$Layout.root_id
    $runId = [string]$Layout.run_id
    if ($rootId -notmatch '\A[0-9a-f]{32}\z' -or $runId -notmatch '\A(?:scheduled|job)-[0-9a-f]{32}\z') {
        throw 'fixture cleanup ownership identity is invalid'
    }
    if ([IO.Path]::GetFileName($resolved) -cne "$rootId Ω fixture space") {
        throw 'fixture cleanup target identity drifted'
    }
    Assert-MeshFixturePathHasNoReparsePoint -Path $resolved
    $target = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if (-not $target.PSIsContainer) { throw 'fixture cleanup target is not a directory' }
    $expectedMarker = Join-Path $resolved '.codex-agent-mesh-fixture-owner'
    $suppliedMarker = [IO.Path]::GetFullPath([string]$Layout.marker_path)
    if (-not $suppliedMarker.Equals($expectedMarker,[StringComparison]::Ordinal)) { throw 'fixture cleanup marker path drifted' }
    $marker = Get-Item -LiteralPath $expectedMarker -Force -ErrorAction Stop
    if ($marker.PSIsContainer -or ($marker.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'fixture ownership marker is not an exact regular file' }
    if ($marker.Length -gt 512) { throw 'fixture ownership marker exceeds its bound' }
    $expectedContents = "codex-agent-mesh-live-fixture-v1`nrun_id=$runId`nroot_id=$rootId`n"
    $actualMarker = [IO.File]::ReadAllText($expectedMarker,[Text.UTF8Encoding]::new($false))
    if ($actualMarker -cne $expectedContents) { throw 'fixture ownership marker contents drifted' }
    Assert-MeshFixtureTreeHasNoReparsePoint -Root $resolved
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

function Wait-MeshBoundedDrain {
    param(
        [Parameter(Mandatory)][BoundedStreamDrain]$Drain,
        [Parameter(Mandatory)][Diagnostics.Process]$Process,
        [Parameter(Mandatory)][ValidateSet('stdout','stderr')][string]$StreamName
    )
    if ($Drain.WaitForCompletion(2000)) { return }
    if ($StreamName -eq 'stdout') { $Process.StandardOutput.BaseStream.Dispose() } else { $Process.StandardError.BaseStream.Dispose() }
    if (-not $Drain.WaitForCompletion(500)) { throw "bounded $StreamName drain did not quiesce" }
}

function Invoke-MeshControl {
    param(
        [Parameter(Mandatory)][string]$RuntimePath,
        [Parameter(Mandatory)][ValidateSet('setup','status','start','remove')][string]$Operation,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [ValidateRange(1,60000)][int]$TimeoutMs = 30000
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $RuntimePath
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @($Operation,'--install-slot','stable')) { [void]$start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($start)
    $stdoutDrain = [BoundedStreamDrain]::Start($process.StandardOutput.BaseStream,65536,65536)
    $stderrDrain = [BoundedStreamDrain]::Start($process.StandardError.BaseStream,65536,4096)
    try {
        if (-not $process.WaitForExit($TimeoutMs)) {
            try { $process.Kill($true) } catch {}
            if (-not $process.WaitForExit(2000)) { throw "$Operation control process did not terminate after bounded kill" }
            throw "$Operation control process timed out"
        }
        Wait-MeshBoundedDrain -Drain $stdoutDrain -Process $process -StreamName stdout
        Wait-MeshBoundedDrain -Drain $stderrDrain -Process $process -StreamName stderr
        if ($stdoutDrain.Truncated) { throw "$Operation stdout exceeded the redacted 64 KiB fixture bound" }
        if ($stderrDrain.Truncated) { throw "$Operation stderr exceeded the redacted 64 KiB / 4 KiB-line fixture bound" }
        $stdout = $stdoutDrain.CapturedUtf8Text()
        if ($stdout.EndsWith("`r`n",[StringComparison]::Ordinal)) { $stdout = $stdout.Substring(0,$stdout.Length-2) }
        elseif ($stdout.EndsWith("`n",[StringComparison]::Ordinal)) { $stdout = $stdout.Substring(0,$stdout.Length-1) }
        $lines = @($stdout -split "`r?`n")
        if ($lines.Count -ne 1) { throw "$Operation emitted $($lines.Count) stdout lines; expected one" }
        $body = $lines[0] | ConvertFrom-Json -Depth 64 -ErrorAction Stop
        [pscustomobject]@{
            exit_code = $process.ExitCode
            body = $body
            stderr_bytes = $stderrDrain.ObservedBytes
            stderr_sha256 = if ($stderrDrain.ObservedBytes) { $stderrDrain.CapturedSha256Hex() } else { $null }
            stderr_truncated = $stderrDrain.Truncated
            stderr_maximum_line_bytes = $stderrDrain.MaximumLineBytes
        }
    } finally {
        if (-not $process.HasExited) {
            try { $process.Kill($true) } catch {}
            [void]$process.WaitForExit(2000)
        }
        $drainFailure = $null
        try { Wait-MeshBoundedDrain -Drain $stdoutDrain -Process $process -StreamName stdout } catch { $drainFailure = 'stdout' }
        try { Wait-MeshBoundedDrain -Drain $stderrDrain -Process $process -StreamName stderr } catch { if (-not $drainFailure) { $drainFailure = 'stderr' } }
        if (-not $drainFailure) {
            if ($stdoutDrain.Truncated) { $drainFailure = 'stdout-bound' }
            elseif ($stderrDrain.Truncated) { $drainFailure = 'stderr-bound' }
        }
        $process.Dispose()
        if ($drainFailure) { throw "$Operation control process violated the redacted bounded-output contract ($drainFailure)" }
    }
}

function Get-MeshInstallRecord {
    $localData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    $path = Join-Path $localData 'codex-agent-mesh\slots\stable\install.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -gt 65536) { throw 'install record exceeds fixture read limit' }
    $record = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json -Depth 64 -ErrorAction Stop
    [pscustomobject]@{
        path = $path
        bytes = $bytes
        digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        record = $record
    }
}

function Get-MeshTaskEvidence {
    param([Parameter(Mandatory)][string]$TaskPath)
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    $folder = $service.GetFolder('\')
    try { $task = $folder.GetTask($TaskPath) } catch { return $null }
    $definition = $task.Definition
    $registration = $definition.RegistrationInfo
    $principal = $definition.Principal
    $principalIdentity = [string]$principal.UserId
    $principalSid = if ($principalIdentity.StartsWith('S-1-')) {
        $principalIdentity
    } else {
        ([Security.Principal.NTAccount]::new($principalIdentity).Translate([Security.Principal.SecurityIdentifier])).Value
    }
    $actions = $definition.Actions
    $triggers = $definition.Triggers
    $settings = $definition.Settings
    $action = if ($actions.Count -eq 1) { $actions.Item(1) } else { $null }
    $instances = $task.GetInstances(0)
    $pids = @()
    for ($index = 1; $index -le $instances.Count; $index++) { $pids += [int]$instances.Item($index).EnginePID }
    $xmlBytes = [Text.Encoding]::Unicode.GetBytes([string]$task.Xml)
    $state = switch ([int]$task.State) {
        0 { 'UNKNOWN' }
        1 { 'DISABLED' }
        2 { 'QUEUED' }
        3 { 'READY' }
        4 { 'RUNNING' }
        default { 'INVALID' }
    }
    [pscustomobject]@{
        path = [string]$task.Path
        name = [string]$task.Name
        owner_uri = [string]$registration.Source
        registration_uri = [string]$registration.URI
        principal_identity = $principalIdentity
        user_sid = $principalSid
        logon_type = [int]$principal.LogonType
        run_level = [int]$principal.RunLevel
        trigger_count = [int]$triggers.Count
        action_count = [int]$actions.Count
        action_type = if ($action) { [int]$action.Type } else { $null }
        action_path = if ($action) { [string]$action.Path } else { $null }
        action_arguments = if ($action) { [string]$action.Arguments } else { $null }
        working_directory = if ($action) { [string]$action.WorkingDirectory } else { $null }
        enabled = [bool]$task.Enabled
        allow_demand_start = [bool]$settings.AllowDemandStart
        execution_time_limit = [string]$settings.ExecutionTimeLimit
        running_instance_pids = $pids
        state = $state
        last_task_result = [int]$task.LastTaskResult
        xml_sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($xmlBytes)).ToLowerInvariant()
    }
}

function Test-MeshExactTaskOwnership {
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)]$Task,
        [Parameter(Mandatory)][string]$CurrentSid
    )
    $expectedPath = [string]$Record.scheduled_task.task_path
    $expectedOwner = "urn:codex-agent-mesh:daemon:$($Record.install_id)"
    return $Task.path -eq $expectedPath -and
        $Task.registration_uri -eq $expectedPath -and
        $Task.owner_uri -eq $expectedOwner -and
        $Task.user_sid -eq $CurrentSid -and
        $Task.trigger_count -eq 0 -and
        $Task.action_count -eq 1 -and
        $Task.action_type -eq 0 -and
        $Task.action_arguments -eq 'daemon --install-slot stable' -and
        $Task.execution_time_limit -eq 'PT0S' -and
        $Task.allow_demand_start
}

function Get-MeshRuntimeEvidence {
    param([Parameter(Mandatory)][string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $certificateDigest = if ($signature.SignerCertificate) {
        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($signature.SignerCertificate.RawData)).ToLowerInvariant()
    } else { $null }
    [pscustomobject]@{
        sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
        byte_length = $bytes.Length
        signature_status = $signature.Status.ToString()
        signer_certificate_sha256 = $certificateDigest
    }
}

function Invoke-MeshRpcOnce {
    param(
        [Parameter(Mandatory)][string]$RuntimePath,
        [Parameter(Mandatory)]$Request,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [int]$TimeoutMs = 10000
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $RuntimePath
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @('bridge-bootstrap','--stdio','--install-slot','stable')) { [void]$start.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($start)
    $stderrDrain = [BoundedStreamDrain]::Start($process.StandardError.BaseStream,65536,4096)
    try {
        $payload = [Text.Encoding]::UTF8.GetBytes(($Request | ConvertTo-Json -Compress -Depth 64))
        $prefix = [BitConverter]::GetBytes([uint32]$payload.Length)
        $process.StandardInput.BaseStream.Write($prefix,0,4)
        $process.StandardInput.BaseStream.Write($payload,0,$payload.Length)
        $process.StandardInput.BaseStream.Flush()
        $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
        $header = [byte[]]::new(4)
        Read-MeshStreamExact -Stream $process.StandardOutput.BaseStream -Buffer $header -Deadline $deadline -Description 'response header'
        $length = [BitConverter]::ToUInt32($header,0)
        if ($length -eq 0 -or $length -gt 8388608) { throw 'native bridge returned invalid frame length' }
        $response = [byte[]]::new($length)
        Read-MeshStreamExact -Stream $process.StandardOutput.BaseStream -Buffer $response -Deadline $deadline -Description 'response body'
        return ([Text.Encoding]::UTF8.GetString($response) | ConvertFrom-Json -Depth 64 -ErrorAction Stop)
    } finally {
        try { $process.StandardInput.Close() } catch {}
        if (-not $process.HasExited) { try { $process.Kill($true) } catch {} }
        if (-not $process.WaitForExit(2000)) {
            try { $process.Kill($true) } catch {}
            [void]$process.WaitForExit(1000)
        }
        try {
            Wait-MeshBoundedDrain -Drain $stderrDrain -Process $process -StreamName stderr
            if ($stderrDrain.Truncated) { throw 'native bridge stderr exceeded the redacted 64 KiB / 4 KiB-line fixture bound' }
        } finally {
            $process.Dispose()
        }
    }
}

function Read-MeshStreamExact {
    param(
        [Parameter(Mandatory)][IO.Stream]$Stream,
        [Parameter(Mandatory)][byte[]]$Buffer,
        [Parameter(Mandatory)][DateTime]$Deadline,
        [Parameter(Mandatory)][string]$Description
    )
    $offset = 0
    while ($offset -lt $Buffer.Length) {
        $remaining = [int][Math]::Max(0,($Deadline - [DateTime]::UtcNow).TotalMilliseconds)
        if ($remaining -eq 0) { throw "native bridge $Description timed out" }
        $readTask = $Stream.ReadAsync($Buffer,$offset,$Buffer.Length-$offset)
        if (-not $readTask.Wait($remaining)) { throw "native bridge $Description timed out" }
        $count = $readTask.Result
        if ($count -eq 0) { throw "native bridge closed during $Description" }
        $offset += $count
    }
}

function Initialize-MeshFixtureNative {
    if ('MeshFixtureNative' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class MeshFixtureNative {
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint TOKEN_QUERY = 0x0008;
    const int TokenElevationType = 18;
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr token, int infoClass, out int value, int length, out int returned);
    [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CommandLineToArgvW(string command, out int count);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    public static bool IsCurrentProcessInAnyJob() { bool result; if (!IsProcessInJob(Process.GetCurrentProcess().Handle, IntPtr.Zero, out result)) throw new Win32Exception(); return result; }
    public static bool IsProcessInSpecificJob(int pid, IntPtr job) { IntPtr process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,false,(uint)pid); if(process==IntPtr.Zero) throw new Win32Exception(); try { bool result; if(!IsProcessInJob(process,job,out result)) throw new Win32Exception(); return result; } finally { CloseHandle(process); } }
    public static string CurrentTokenElevationType() { IntPtr token; if(!OpenProcessToken(Process.GetCurrentProcess().Handle,TOKEN_QUERY,out token)) throw new Win32Exception(); try { int value, returned; if(!GetTokenInformation(token,TokenElevationType,out value,4,out returned) || returned!=4) throw new Win32Exception(); return value==1?"Default":value==2?"Full":value==3?"Limited":"Unknown"; } finally { CloseHandle(token); } }
    public static string[] ParseCommandLine(string command) { int count; IntPtr values=CommandLineToArgvW(command,out count); if(values==IntPtr.Zero) throw new Win32Exception(); try { var result=new string[count]; for(int i=0;i<count;i++) result[i]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(values,i*IntPtr.Size)); return result; } finally { LocalFree(values); } }
}
'@
}

if ($IsWindows) { Initialize-MeshFixtureNative }
