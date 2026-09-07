using System.Diagnostics;

namespace WinHUB.Security;

internal sealed record TaskResourceLimits(int MemoryMb = 2048, int Processes = 32, int CpuPercent = 50)
{
    internal void Validate()
    {
        if (MemoryMb is < 128 or > 131072 || Processes is < 4 or > 1024 || CpuPercent is < 1 or > 100)
            throw new InvalidDataException("Task limits require MemoryMb=128..131072, Processes=4..1024 and CpuPercent=1..100.");
    }
}

internal static class LinuxTaskProcess
{
    internal static ProcessStartInfo Command(ProcessStartInfo task, TaskResourceLimits limits, int timeout, string unit)
    {
        limits.Validate();
        if (!string.IsNullOrEmpty(task.Arguments) || !task.FileName.StartsWith('/'))
            throw new InvalidDataException("Task execution requires an absolute executable and structured arguments.");
        var start = new ProcessStartInfo("/usr/bin/systemd-run")
            { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string arg in new[] { "--quiet", "--pipe", "--wait", "--collect", "--service-type=exec", "--unit=" + unit,
            "--property=MemoryMax=" + limits.MemoryMb + "M", "--property=TasksMax=" + limits.Processes,
            "--property=MemorySwapMax=0", "--property=OOMPolicy=kill",
            "--property=CPUQuota=" + ((long)limits.CpuPercent * Environment.ProcessorCount) + "%",
            "--property=RuntimeMaxSec=" + timeout, "--property=TimeoutStopSec=5s", "--property=KillMode=control-group",
            "--property=BindsTo=winhub-linux-agent.service", "--property=After=winhub-linux-agent.service",
            "--property=UMask=0077", "--property=LimitCORE=0", "--working-directory=" + task.WorkingDirectory,
            "--", task.FileName }) start.ArgumentList.Add(arg);
        foreach (string arg in task.ArgumentList) start.ArgumentList.Add(arg);
        return start;
    }

    internal static async Task<(string Output, string Error, int ExitCode)> RunAsync(ProcessStartInfo start,
        int timeout, int maximum, TaskResourceLimits limits, CancellationToken token)
    {
        CheckPrerequisites();
        if (!OperatingSystem.IsLinux() || !Directory.Exists("/run/systemd/system")
            || string.IsNullOrEmpty(Environment.GetEnvironmentVariable("INVOCATION_ID")))
            throw new InvalidDataException("Production tasks require the installed systemd agent service and cgroup v2. No unrestricted fallback was used.");
        string unit = "winhub-task-" + Guid.NewGuid().ToString("N") + ".service";
        try { return await ProductionSecurity.RunCapturedAsync(Command(start, limits, timeout, unit), timeout, maximum, token); }
        finally
        {
            // systemd owns the task processes, not the systemd-run client process group.
            // Explicit stop also cleans up daemons which closed stdout and outlived the main script.
            var stop = new ProcessStartInfo("/usr/bin/systemctl")
                { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (string arg in new[] { "stop", unit }) stop.ArgumentList.Add(arg);
            await ProductionSecurity.RunCapturedAsync(stop, 15, 16384, CancellationToken.None);
        }
    }

    internal static void CheckPrerequisites()
    {
        if (!OperatingSystem.IsLinux()) return;
        if (!File.Exists("/usr/bin/systemd-run") || !File.Exists("/sys/fs/cgroup/cgroup.controllers"))
            throw new InvalidDataException("systemd-run and cgroup v2 are required for production tasks.");
        // sysfs is kernel-owned; security-path symlink restrictions for local secrets do not apply.
        var controllers = File.ReadAllText("/sys/fs/cgroup/cgroup.controllers").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (new[] { "cpu", "memory", "pids" }.Any(controller => !controllers.Contains(controller)))
            throw new InvalidDataException("cgroup v2 cpu, memory and pids controllers must be available.");
    }
}
