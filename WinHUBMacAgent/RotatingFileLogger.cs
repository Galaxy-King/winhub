using System.Text;
using Microsoft.Extensions.Logging;

namespace WinHUBMacAgent;

internal sealed class RotatingFileLoggerProvider : ILoggerProvider
{
    private readonly string _logPath;
    private readonly string _errorLogPath;
    private readonly long _maxBytes;
    private readonly int _retainedFiles;
    private readonly object _sync = new();

    public RotatingFileLoggerProvider(string logPath, string errorLogPath, long maxBytes, int retainedFiles)
    {
        _logPath = logPath;
        _errorLogPath = errorLogPath;
        _maxBytes = Math.Max(1024 * 1024, maxBytes);
        _retainedFiles = Math.Clamp(retainedFiles, 1, 30);
    }

    public ILogger CreateLogger(string categoryName) => new RotatingFileLogger(this, categoryName);
    public void Dispose() { }

    private void Write(LogLevel level, string category, EventId eventId, string message, Exception? exception)
    {
        string eventText = eventId.Id == 0 ? "" : $" event={eventId.Id}";
        string line = $"{DateTimeOffset.UtcNow:O} [{level}] {category}{eventText}: {message}";
        if (exception != null) line += Environment.NewLine + exception;
        line += Environment.NewLine;
        byte[] bytes = Encoding.UTF8.GetBytes(line);

        lock (_sync)
        {
            AppendWithRotation(_logPath, bytes);
            if (level >= LogLevel.Error)
                AppendWithRotation(_errorLogPath, bytes);
        }
    }

    private void AppendWithRotation(string path, byte[] bytes)
    {
        try
        {
            string? directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
            long currentLength = File.Exists(path) ? new FileInfo(path).Length : 0;
            if (currentLength > 0 && currentLength + bytes.Length > _maxBytes)
                Rotate(path);
            using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            stream.Write(bytes, 0, bytes.Length);
        }
        catch
        {
            // Logging must never terminate the fleet agent. launchd stderr remains available
            // for fatal runtime failures that happen before the provider can write.
        }
    }

    private void Rotate(string path)
    {
        try { File.Delete($"{path}.{_retainedFiles}"); } catch { }
        for (int index = _retainedFiles - 1; index >= 1; index--)
        {
            string source = $"{path}.{index}";
            string destination = $"{path}.{index + 1}";
            if (!File.Exists(source)) continue;
            try { File.Move(source, destination, overwrite: true); } catch { }
        }
        try { File.Move(path, $"{path}.1", overwrite: true); } catch { }
    }

    private sealed class RotatingFileLogger : ILogger
    {
        private readonly RotatingFileLoggerProvider _provider;
        private readonly string _category;

        public RotatingFileLogger(RotatingFileLoggerProvider provider, string category)
        {
            _provider = provider;
            _category = category;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            _provider.Write(logLevel, _category, eventId, formatter(state, exception), exception);
        }
    }
}
