using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WinHUBLinuxAgent;

// Managed Windows validation also exercises the linked Job Object implementation.
if (WinHUB.Security.WindowsTaskProcess.TryRunChild(args)) return;
if (WinHUB.Security.ReleaseCommand.TryRun(args, "linux")) return;

if (args.Any(arg => arg.Equals("--version", StringComparison.OrdinalIgnoreCase) || arg.Equals("-v", StringComparison.OrdinalIgnoreCase)))
{
    Console.WriteLine(AgentBuildInfo.Version);
    return;
}

if (args.Any(arg => arg.Equals("--self-test", StringComparison.OrdinalIgnoreCase)))
{
    Worker.RunProtocolSelfTest();
    Worker.RunProductionSelfTest();
    Console.WriteLine("WinHUB Linux Agent protocol self-test: OK");
    return;
}

int migrateStateIndex = Array.FindIndex(args, arg => arg.Equals("--migrate-task-signing-state", StringComparison.OrdinalIgnoreCase));
if (migrateStateIndex >= 0)
{
    if (migrateStateIndex + 2 >= args.Length)
        throw new ArgumentException("Usage: WinHUBLinuxAgent --migrate-task-signing-state CONFIG_PATH DATA_DIRECTORY");
    bool migrated = Worker.MigrateTaskSigningState(args[migrateStateIndex + 1], args[migrateStateIndex + 2]);
    Console.WriteLine(migrated ? "WinHUB task signing state is preserved." : "No pinned WinHUB task signing state was present.");
    return;
}

int validateConfigIndex = Array.FindIndex(args, arg => arg.Equals("--validate-config", StringComparison.OrdinalIgnoreCase));
if (validateConfigIndex >= 0)
{
    if (validateConfigIndex + 1 >= args.Length) throw new ArgumentException("Usage: --validate-config CONFIG_PATH");
    Worker.ValidateConfigFile(args[validateConfigIndex + 1]);
    Console.WriteLine("WinHUB production pin configuration: OK (offline validation; no network request made)");
    return;
}

int extractIndex = Array.FindIndex(args, arg => arg.Equals("--extract-update", StringComparison.OrdinalIgnoreCase));
int checkServerIndex = Array.FindIndex(args, arg => arg.Equals("--check-update-server", StringComparison.OrdinalIgnoreCase));
if (checkServerIndex >= 0)
{
    if (checkServerIndex + 1 >= args.Length) throw new ArgumentException("Usage: --check-update-server CONFIG_PATH");
    Worker.ValidateConfigFile(args[checkServerIndex + 1]);
    await WinHUB.Security.UpdatePreflight.CheckServerAsync(args[checkServerIndex + 1]);
    Console.WriteLine("WinHUB pinned HTTPS preflight: OK (no enrollment or tasks requested)");
    return;
}

if (extractIndex >= 0)
{
    if (extractIndex + 2 >= args.Length) throw new ArgumentException("Usage: --extract-update PACKAGE EMPTY_STAGING_DIRECTORY");
    WinHUB.Security.SafeArchive.Extract(args[extractIndex + 1], args[extractIndex + 2]);
    return;
}

if (args.Length != 0) throw new ArgumentException("Unknown command. No service was started.");

var builder = Host.CreateDefaultBuilder(args)
    .UseSystemd()
    .ConfigureServices(services =>
    {
        services.AddHostedService<Worker>();
    });

var host = builder.Build();
host.Run();
