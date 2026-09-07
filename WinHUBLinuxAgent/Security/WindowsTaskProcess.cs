using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32.SafeHandles;

namespace WinHUB.Security;

internal sealed record TaskLaunch(string FileName, string[] Arguments, string WorkingDirectory);
[JsonSerializable(typeof(TaskLaunch))]
internal partial class TaskLaunchJsonContext : JsonSerializerContext { }

internal static class WindowsTaskProcess
{
    // The wrapper starts without task data. The parent attaches it to its job BEFORE
    // sending a bounded launch frame. Therefore no task code can run before containment.
    internal static bool TryRunChild(string[] args)
    {
        if (args.Length != 1 || args[0] != "--task-child") return false;
        try
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            var input = Console.OpenStandardInput();
            byte[] lengthBytes = new byte[4];
            input.ReadExactly(lengthBytes);
            int length = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
            if (length is < 1 or > 65536) throw new InvalidDataException("Invalid task launch frame.");
            byte[] data = new byte[length];
            input.ReadExactly(data);
            if (!IsProcessInJob(GetCurrentProcess(), IntPtr.Zero, out bool contained) || !contained)
                throw new IOException("Task wrapper must belong to a Windows Job Object.");
            var task = JsonSerializer.Deserialize(data, TaskLaunchJsonContext.Default.TaskLaunch)
                ?? throw new InvalidDataException("Task launch is empty.");
            if (!Path.IsPathFullyQualified(task.FileName)) throw new InvalidDataException("Absolute task executable required.");
            var start = new ProcessStartInfo(task.FileName) { UseShellExecute = false, WorkingDirectory = task.WorkingDirectory };
            foreach (string argument in task.Arguments) start.ArgumentList.Add(argument);
            using var child = Process.Start(start) ?? throw new IOException("Could not start bounded task.");
            child.WaitForExit();
            Environment.ExitCode = child.ExitCode;
        }
        catch (Exception ex) { Console.Error.WriteLine("Task wrapper rejected: " + ex.Message); Environment.ExitCode = 1; }
        return true;
    }

    internal static async Task<(string Output, string Error, int ExitCode)> RunAsync(ProcessStartInfo task,
        int timeout, int maximum, TaskResourceLimits limits, CancellationToken token)
    {
        limits.Validate();
        if (!OperatingSystem.IsWindows() || !string.IsNullOrEmpty(task.Arguments))
            throw new InvalidDataException("Windows task runner requires structured arguments.");
        using var job = CreateJobObjectW(IntPtr.Zero, null);
        if (job.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        var information = new ExtendedLimits
        {
            Basic = new BasicLimits { Flags = 0x2000 /* KILL_ON_JOB_CLOSE */ | 0x200 /* JOB_MEMORY */ | 0x8 /* ACTIVE_PROCESS */,
                ActiveProcesses = (uint)limits.Processes },
            JobMemory = (UIntPtr)((ulong)limits.MemoryMb * 1024 * 1024)
        };
        if (!SetInformationJobObject(job, 9, ref information, (uint)Marshal.SizeOf<ExtendedLimits>()))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        var cpu = new CpuLimit { Flags = 1 | 4 /* ENABLE | HARD_CAP */, Rate = (uint)limits.CpuPercent * 100 };
        if (!SetInformationJobObjectCpu(job, 15, ref cpu, 8)) throw new Win32Exception(Marshal.GetLastWin32Error());
        var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        if (string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath), "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            // CLI managed validation only. NativeAOT/single-file releases use ProcessPath directly.
            start.ArgumentList.Add(Environment.GetCommandLineArgs()[0]);
        }
        start.ArgumentList.Add("--task-child");
        start.Environment.Clear();
        foreach (var variable in task.Environment) start.Environment[variable.Key] = variable.Value;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(timeout));
        using var process = Process.Start(start) ?? throw new IOException("Could not start task wrapper.");
        try
        {
            if (!AssignProcessToJobObject(job, process.Handle)) throw new Win32Exception(Marshal.GetLastWin32Error());
            byte[] data = JsonSerializer.SerializeToUtf8Bytes(new TaskLaunch(task.FileName, task.ArgumentList.ToArray(), task.WorkingDirectory), TaskLaunchJsonContext.Default.TaskLaunch);
            if (data.Length > 65536) throw new InvalidDataException("Task launch frame too large.");
            byte[] length = new byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(length, data.Length);
            await process.StandardInput.BaseStream.WriteAsync(length, deadline.Token);
            await process.StandardInput.BaseStream.WriteAsync(data, deadline.Token);
            process.StandardInput.Close();
            var stdout = ProductionSecurity.CaptureAsync(process.StandardOutput, maximum, deadline);
            var stderr = ProductionSecurity.CaptureAsync(process.StandardError, maximum, deadline);
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(deadline.Token));
            return (stdout.Result, stderr.Result, process.ExitCode);
        }
        finally
        {
            // Close kills every member, including grandchildren after their parent has exited.
            job.Dispose();
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await process.WaitForExitAsync(cleanup.Token);
        }
    }

    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits
    { public long ProcessTime, JobTime; public uint Flags; public UIntPtr MinimumWorkingSet, MaximumWorkingSet; public uint ActiveProcesses; public UIntPtr Affinity; public uint Priority, Scheduling; }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits
    { public BasicLimits Basic; public IoCounters Io; public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory; }
    [StructLayout(LayoutKind.Sequential)] private struct CpuLimit { public uint Flags, Rate; }
    private sealed class JobHandle : SafeHandleZeroOrMinusOneIsInvalid
    { public JobHandle() : base(true) { } protected override bool ReleaseHandle() => CloseHandle(handle); }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern JobHandle CreateJobObjectW(IntPtr attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetInformationJobObject(JobHandle job, int infoClass, ref ExtendedLimits information, uint length);
    [DllImport("kernel32.dll", EntryPoint = "SetInformationJobObject", SetLastError = true)] private static extern bool SetInformationJobObjectCpu(JobHandle job, int infoClass, ref CpuLimit information, uint length);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AssignProcessToJobObject(JobHandle job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
}
