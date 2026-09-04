using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Text;
using WinHUBAgent;

if (args.Any(arg => arg.Equals("--version", StringComparison.OrdinalIgnoreCase) || arg.Equals("-v", StringComparison.OrdinalIgnoreCase)))
{
    Console.WriteLine(AgentBuildInfo.Version);
    return;
}

if (args.Any(arg => arg.Equals("--self-test", StringComparison.OrdinalIgnoreCase)))
{
    Worker.RunProductionSelfTest();
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
if (extractIndex >= 0)
{
    if (extractIndex + 2 >= args.Length) throw new ArgumentException("Usage: --extract-update PACKAGE EMPTY_STAGING_DIRECTORY");
    WinHUB.Security.SafeArchive.Extract(args[extractIndex + 1], args[extractIndex + 2]);
    return;
}

if (args.Length != 0) throw new ArgumentException("Unknown command. Supported: --version, --self-test, --validate-config, --extract-update. No service was started.");

var builder = Host.CreateDefaultBuilder(args)
    .UseWindowsService(options =>
    {
        options.ServiceName = "WinHUBAgent";
    })
    .ConfigureLogging(logging =>
    {
        logging.AddProvider(new RollingFileLoggerProvider(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "WinHUB",
                "logs",
                "agent.log"
            ),
            maxBytes: 1_048_576,
            retainedFiles: 7,
            retentionDays: 14
        ));
    })
    .ConfigureServices(services =>
    {
        services.AddHostedService<Worker>();
    });

var host = builder.Build();
host.Run();

internal sealed class RollingFileLoggerProvider : ILoggerProvider
{
    private readonly string _path;
    private readonly long _maxBytes;
    private readonly int _retainedFiles;
    private readonly int _retentionDays;
    private readonly object _sync = new();
    private bool _directorySecured;

    public RollingFileLoggerProvider(string path, long maxBytes, int retainedFiles, int retentionDays)
    {
        _path = path;
        _maxBytes = Math.Max(262_144, maxBytes);
        _retainedFiles = Math.Max(1, retainedFiles);
        _retentionDays = Math.Max(1, retentionDays);
    }

    public ILogger CreateLogger(string categoryName) => new RollingFileLogger(categoryName, this);

    public void Dispose() { }

    private void Write(string category, LogLevel level, EventId eventId, string message, Exception? exception)
    {
        if (level < LogLevel.Information) return;

        lock (_sync)
        {
            try
            {
                string? directory = Path.GetDirectoryName(_path);
                if (!string.IsNullOrWhiteSpace(directory))
                {
                    if (!_directorySecured)
                    {
                        string dataDirectory = Path.GetDirectoryName(directory)!;
                        WinHUB.Security.ProductionSecurity.RejectLinks(_path);
                        Directory.CreateDirectory(dataDirectory);
                        Worker.SecureWindowsPath(dataDirectory, isDirectory: true);
                        Directory.CreateDirectory(directory);
                        Worker.SecureWindowsPath(directory, isDirectory: true);
                        if (File.Exists(_path)) Worker.SecureWindowsPath(_path, isDirectory: false);
                        _directorySecured = true;
                    }
                    Directory.CreateDirectory(directory);
                }
                WinHUB.Security.ProductionSecurity.RejectLinks(_path);
                RotateIfNeeded();
                CleanupOldLogs();

                string line = $"{DateTimeOffset.UtcNow:O} [{level}] {category} {message}";
                if (exception != null)
                {
                    line += $" | {exception.GetType().Name}: {exception.Message}";
                }
                File.AppendAllText(_path, line + Environment.NewLine, new UTF8Encoding(false));
            }
            catch
            {
                // Logging must never stop the service.
            }
        }
    }

    private void RotateIfNeeded()
    {
        if (!File.Exists(_path) || new FileInfo(_path).Length < _maxBytes) return;

        string oldest = $"{_path}.{_retainedFiles}";
        if (File.Exists(oldest)) File.Delete(oldest);

        for (int index = _retainedFiles - 1; index >= 1; index--)
        {
            string source = $"{_path}.{index}";
            string destination = $"{_path}.{index + 1}";
            if (File.Exists(source))
            {
                File.Move(source, destination, overwrite: true);
            }
        }

        File.Move(_path, $"{_path}.1", overwrite: true);
    }

    private void CleanupOldLogs()
    {
        string? directory = Path.GetDirectoryName(_path);
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory)) return;

        DateTime cutoff = DateTime.UtcNow.AddDays(-_retentionDays);
        foreach (string file in Directory.EnumerateFiles(directory, "agent.log*"))
        {
            try
            {
                if (File.GetLastWriteTimeUtc(file) < cutoff)
                {
                    File.Delete(file);
                }
            }
            catch { }
        }
    }

    private sealed class RollingFileLogger : ILogger
    {
        private readonly string _category;
        private readonly RollingFileLoggerProvider _provider;

        public RollingFileLogger(string category, RollingFileLoggerProvider provider)
        {
            _category = category;
            _provider = provider;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            _provider.Write(_category, logLevel, eventId, formatter(state, exception), exception);
        }
    }
}
