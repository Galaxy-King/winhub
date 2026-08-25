using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WinHUBLinuxAgent;

if (args.Any(arg => arg.Equals("--version", StringComparison.OrdinalIgnoreCase) || arg.Equals("-v", StringComparison.OrdinalIgnoreCase)))
{
    Console.WriteLine(AgentBuildInfo.Version);
    return;
}

if (args.Any(arg => arg.Equals("--self-test", StringComparison.OrdinalIgnoreCase)))
{
    Worker.RunProtocolSelfTest();
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

var builder = Host.CreateDefaultBuilder(args)
    .UseSystemd()
    .ConfigureServices(services =>
    {
        services.AddHostedService<Worker>();
    });

var host = builder.Build();
host.Run();
