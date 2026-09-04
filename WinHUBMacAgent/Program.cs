using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WinHUBMacAgent;
using WinHUBLinuxAgent;

if (args.Any(arg => arg.Equals("--version", StringComparison.OrdinalIgnoreCase) || arg.Equals("-v", StringComparison.OrdinalIgnoreCase)))
{
    Console.WriteLine(AgentBuildInfo.Version);
    return;
}

if (args.Any(arg => arg.Equals("--self-test", StringComparison.OrdinalIgnoreCase)))
{
    Worker.RunProtocolSelfTest();
    Console.WriteLine("WinHUB macOS Agent protocol self-test: OK");
    return;
}

if (!OperatingSystem.IsMacOS())
    throw new PlatformNotSupportedException("WinHUBMacAgent can only run on macOS.");

var host = Host.CreateDefaultBuilder(args)
    .ConfigureLogging(logging =>
    {
        logging.ClearProviders();
        logging.AddProvider(new RotatingFileLoggerProvider(
            "/Library/Logs/WinHUB/agent.log",
            "/Library/Logs/WinHUB/agent-error.log",
            10L * 1024 * 1024,
            7));
    })
    .ConfigureServices(services => services.AddHostedService<Worker>())
    .Build();
host.Run();
