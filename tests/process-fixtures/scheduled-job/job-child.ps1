param(
    [Parameter(Mandatory)][ValidateSet('start','wait')][string]$Mode,
    [Parameter(Mandatory)][string]$RuntimePath,
    [Parameter(Mandatory)][string]$WorkingDirectory,
    [Parameter(Mandatory)][string]$ReadyPath,
    [Parameter(Mandatory)][string]$BreakawayPath,
    [string]$CompletionPath,
    [string]$TaskId,
    [long]$AfterSeq = 0
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not ('BoundedStreamDrain' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'BoundedStreamDrain.cs') }

function Wait-BoundedChildDrain {
    param(
        [Parameter(Mandatory)][BoundedStreamDrain]$Drain,
        [Parameter(Mandatory)][Diagnostics.Process]$Process,
        [Parameter(Mandatory)][ValidateSet('stdout','stderr')][string]$StreamName
    )
    if ($Drain.WaitForCompletion(2000)) { return }
    if ($StreamName -eq 'stdout') { $Process.StandardOutput.BaseStream.Dispose() } else { $Process.StandardError.BaseStream.Dispose() }
    if (-not $Drain.WaitForCompletion(500)) { throw "bounded child $StreamName drain did not quiesce" }
}

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class BreakawayProbe {
  const uint CREATE_BREAKAWAY_FROM_JOB=0x01000000, CREATE_NO_WINDOW=0x08000000;
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct SI { public int cb; public string a,b,c; public int d,e,f,g,h,i,j,k; public short l,m; public IntPtr n,o,p,q; }
  [StructLayout(LayoutKind.Sequential)] struct PI { public IntPtr p,t; public uint pid,tid; }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,string cmd,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref SI si,out PI pi);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr p,uint code);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
  public static int Run(string app,string cmd,string cwd) { var si=new SI(); si.cb=Marshal.SizeOf(si); PI pi; if(!CreateProcess(app,cmd,IntPtr.Zero,IntPtr.Zero,false,CREATE_BREAKAWAY_FROM_JOB|CREATE_NO_WINDOW,IntPtr.Zero,cwd,ref si,out pi)) return Marshal.GetLastWin32Error(); TerminateProcess(pi.p,98); CloseHandle(pi.t); CloseHandle(pi.p); return 0; }
}
'@

$pwsh = (Get-Process -Id $PID).Path
$escaped = $pwsh.Replace('"','\"')
$breakawayError = [BreakawayProbe]::Run($pwsh,('"{0}" -NoProfile -Command "exit 0"' -f $escaped),$WorkingDirectory)
[IO.File]::WriteAllText($BreakawayPath,(@{ attempted = $true; win32_error = $breakawayError } | ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))

if ($Mode -eq 'start') {
    $controlInfo = [Diagnostics.ProcessStartInfo]::new()
    $controlInfo.FileName = $RuntimePath
    $controlInfo.WorkingDirectory = $WorkingDirectory
    $controlInfo.UseShellExecute = $false
    $controlInfo.CreateNoWindow = $true
    $controlInfo.RedirectStandardOutput = $true
    $controlInfo.RedirectStandardError = $true
    foreach ($argument in @('start','--install-slot','stable')) { [void]$controlInfo.ArgumentList.Add($argument) }
    $control = [Diagnostics.Process]::Start($controlInfo)
    [IO.File]::WriteAllText($ReadyPath,"STARTING:$($control.Id)",[Text.UTF8Encoding]::new($false))
    $stdoutDrain = [BoundedStreamDrain]::Start($control.StandardOutput.BaseStream,65536,65536)
    $stderrDrain = [BoundedStreamDrain]::Start($control.StandardError.BaseStream,65536,4096)
    $control.WaitForExit()
    Wait-BoundedChildDrain -Drain $stdoutDrain -Process $control -StreamName stdout
    Wait-BoundedChildDrain -Drain $stderrDrain -Process $control -StreamName stderr
    if ($CompletionPath) {
        $completion = [ordered]@{
            exit_code = $control.ExitCode
            stdout_bytes = $stdoutDrain.ObservedBytes
            stdout_truncated = $stdoutDrain.Truncated
            stderr_bytes = $stderrDrain.ObservedBytes
            stderr_truncated = $stderrDrain.Truncated
            stderr_maximum_line_bytes = $stderrDrain.MaximumLineBytes
        }
        [IO.File]::WriteAllText($CompletionPath,($completion | ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
    }
    Start-Sleep -Seconds 30
    exit
}

if (-not $TaskId) { throw 'wait mode requires TaskId' }
$start = [Diagnostics.ProcessStartInfo]::new()
$start.FileName = $RuntimePath
$start.WorkingDirectory = $WorkingDirectory
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardInput = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
foreach ($argument in @('bridge-bootstrap','--stdio','--install-slot','stable')) { [void]$start.ArgumentList.Add($argument) }
$bridge = [Diagnostics.Process]::Start($start)
$stderrDrain = [BoundedStreamDrain]::Start($bridge.StandardError.BaseStream,65536,4096)
$request = @{ jsonrpc='2.0'; id='fixture-wait'; method='mesh.wait_task'; params=@{ task_id=$TaskId; after_seq=$AfterSeq; limit=200; wait_ms=30000 } }
$payload = [Text.Encoding]::UTF8.GetBytes(($request | ConvertTo-Json -Compress -Depth 16))
$prefix = [BitConverter]::GetBytes([uint32]$payload.Length)
$bridge.StandardInput.BaseStream.Write($prefix,0,4)
$bridge.StandardInput.BaseStream.Write($payload,0,$payload.Length)
$bridge.StandardInput.BaseStream.Flush()
[IO.File]::WriteAllText($ReadyPath,"RPC_SENT:$($bridge.Id)",[Text.UTF8Encoding]::new($false))
$header = [byte[]]::new(4)
[void]$bridge.StandardOutput.BaseStream.Read($header,0,4)
if ($CompletionPath) { [IO.File]::WriteAllText($CompletionPath,'RPC_REPLIED',[Text.UTF8Encoding]::new($false)) }
Start-Sleep -Seconds 30
