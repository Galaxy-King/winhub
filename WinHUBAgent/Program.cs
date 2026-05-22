using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WinHUBAgent;

if (args.Any(arg => arg.Equals("--version", StringComparison.OrdinalIgnoreCase) || arg.Equals("-v", StringComparison.OrdinalIgnoreCase)))
{
    Console.WriteLine(AgentBuildInfo.Version);
    return;
}

var builder = Host.CreateDefaultBuilder(args)
    .UseWindowsService(options =>
    {
        options.ServiceName = "WinHUBAgent";
    })
    .ConfigureServices(services =>
    {
        services.AddHostedService<Worker>();
    });

var host = builder.Build();
host.Run();
