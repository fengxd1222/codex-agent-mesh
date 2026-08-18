using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public sealed class MeshKillOnCloseJob : IDisposable {
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint CREATE_NO_WINDOW = 0x08000000;
    const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    const int JobObjectExtendedLimitInformation = 9;

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct STARTUPINFO { public int cb; public string lpReserved; public string lpDesktop; public string lpTitle; public int dwX; public int dwY; public int dwXSize; public int dwYSize; public int dwXCountChars; public int dwYCountChars; public int dwFillAttribute; public int dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError; }
    [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }
    [StructLayout(LayoutKind.Sequential)] struct JOBOBJECT_BASIC_LIMIT_INFORMATION { public long PerProcessUserTimeLimit; public long PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize; public UIntPtr MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass; public uint SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] struct IO_COUNTERS { public ulong ReadOperationCount; public ulong WriteOperationCount; public ulong OtherOperationCount; public ulong ReadTransferCount; public ulong WriteTransferCount; public ulong OtherTransferCount; }
    [StructLayout(LayoutKind.Sequential)] struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION { public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation; public IO_COUNTERS IoInfo; public UIntPtr ProcessMemoryLimit; public UIntPtr JobMemoryLimit; public UIntPtr PeakProcessMemoryUsed; public UIntPtr PeakJobMemoryUsed; }

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcess(string app, string commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string cwd, ref STARTUPINFO startup, out PROCESS_INFORMATION process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint length, out uint returned);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);

    IntPtr job;
    IntPtr process;
    public int ProcessId { get; private set; }
    public IntPtr JobHandle { get { return job; } }

    public static MeshKillOnCloseJob Launch(string application, string commandLine, string cwd) {
        var owner = new MeshKillOnCloseJob();
        owner.job = CreateJobObject(IntPtr.Zero, null);
        if (owner.job == IntPtr.Zero) throw new Win32Exception();
        var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        int size = Marshal.SizeOf(limits); IntPtr buffer = Marshal.AllocHGlobal(size);
        try { Marshal.StructureToPtr(limits, buffer, false); if (!SetInformationJobObject(owner.job, JobObjectExtendedLimitInformation, buffer, (uint)size)) throw new Win32Exception(); } finally { Marshal.FreeHGlobal(buffer); }
        var startup = new STARTUPINFO(); startup.cb = Marshal.SizeOf(startup);
        PROCESS_INFORMATION pi;
        if (!CreateProcess(application, commandLine, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, cwd, ref startup, out pi)) { owner.Dispose(); throw new Win32Exception(); }
        owner.process = pi.hProcess; owner.ProcessId = (int)pi.dwProcessId;
        try {
            if (!AssignProcessToJobObject(owner.job, pi.hProcess)) throw new Win32Exception();
            if (ResumeThread(pi.hThread) == 0xffffffff) throw new Win32Exception();
        } catch { TerminateProcess(pi.hProcess, 97); owner.Dispose(); throw; }
        finally { CloseHandle(pi.hThread); }
        return owner;
    }

    public void CloseJob() { if (job != IntPtr.Zero) { CloseHandle(job); job = IntPtr.Zero; } }
    public int[] ActiveProcessIds() {
        if (job == IntPtr.Zero) throw new ObjectDisposedException("job");
        const int JobObjectBasicProcessIdList = 3;
        const int maximum = 128;
        int bytes = 8 + IntPtr.Size * maximum;
        IntPtr buffer = Marshal.AllocHGlobal(bytes);
        try {
            uint returned;
            if (!QueryInformationJobObject(job, JobObjectBasicProcessIdList, buffer, (uint)bytes, out returned)) throw new Win32Exception();
            uint count = (uint)Marshal.ReadInt32(buffer, 4);
            if (count > maximum) throw new InvalidOperationException("fixture job process list exceeded bound");
            var ids = new int[count];
            for (int i=0; i<count; i++) ids[i] = checked((int)Marshal.ReadIntPtr(buffer, 8 + i*IntPtr.Size).ToInt64());
            return ids;
        } finally { Marshal.FreeHGlobal(buffer); }
    }
    public void Dispose() { CloseJob(); if (process != IntPtr.Zero) { CloseHandle(process); process = IntPtr.Zero; } }
}
