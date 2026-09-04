using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace WinHUB.Security;

// Linked into both endpoint agents; no server credentials or production pins belong here.
internal static class ProductionSecurity
{
    internal const int MaxApiResponseBytes = 4 * 1024 * 1024;
    internal const long MaxUpdateBytes = 512L * 1024 * 1024;

    internal static string ParsePin(string? value)
    {
        string normalized = (value ?? "").Replace(":", "").Replace(" ", "").Trim();
        if (normalized.Length != 64 || normalized.Any(c => !Uri.IsHexDigit(c)))
            throw new InvalidDataException("ServerCertificateSha256 must be an administrator-provisioned SHA-256 certificate fingerprint (64 hex digits).");
        return normalized.ToUpperInvariant();
    }

    internal static Uri ValidateConfiguration(string serverUrl, string pin, string? nextPin, bool ignoreTls, bool requireSignature)
    {
        if (!Uri.TryCreate(serverUrl, UriKind.Absolute, out Uri? uri) || uri.Scheme != Uri.UriSchemeHttps
            || !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment) || uri.AbsolutePath != "/")
            throw new InvalidDataException("Production ServerUrl must be an HTTPS origin without credentials, path, query or fragment.");
        ParsePin(pin);
        if (!string.IsNullOrWhiteSpace(nextPin)) ParsePin(nextPin);
        if (ignoreTls) throw new InvalidDataException("IgnoreTlsCertificateErrors=true is forbidden in production.");
        if (!requireSignature) throw new InvalidDataException("RequireTaskSignature=false is forbidden in production.");
        return uri;
    }

    internal static bool CertificateMatches(X509Certificate2? certificate, string pin, string? nextPin)
    {
        if (certificate == null) return false;
        try
        {
            // A pin is the trust anchor, including for a self-signed certificate. Never learn it from the network.
            DateTime now = DateTime.UtcNow;
            if (now < certificate.NotBefore.ToUniversalTime() || now > certificate.NotAfter.ToUniversalTime()) return false;
            byte[] actual = certificate.GetCertHash(HashAlgorithmName.SHA256);
            bool matches = CryptographicOperations.FixedTimeEquals(actual, Convert.FromHexString(ParsePin(pin)));
            if (!string.IsNullOrWhiteSpace(nextPin))
                matches |= CryptographicOperations.FixedTimeEquals(actual, Convert.FromHexString(ParsePin(nextPin)));
            return matches;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException or InvalidDataException) { return false; }
    }

    internal static Uri UpdateUri(string serverUrl, string packageUrl)
    {
        var origin = new Uri(serverUrl.TrimEnd('/') + "/");
        var result = new Uri(origin, packageUrl);
        if (result.Scheme != Uri.UriSchemeHttps || !result.Host.Equals(origin.Host, StringComparison.OrdinalIgnoreCase)
            || result.Port != origin.Port || !string.IsNullOrEmpty(result.UserInfo) || !string.IsNullOrEmpty(result.Fragment))
            throw new InvalidDataException("Update packages must use the pinned WinHUB HTTPS origin. Redirects and cross-host downloads are forbidden.");
        return result;
    }

    internal static string ReadText(string path, int maxBytes = MaxApiResponseBytes)
        => Encoding.UTF8.GetString(ReadBytes(path, maxBytes)).TrimStart('\uFEFF');

    internal static byte[] ReadBytes(string path, int maxBytes = MaxApiResponseBytes)
    {
        RejectLinks(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > maxBytes) throw new InvalidDataException("Local agent file exceeds its size limit.");
        using var bytes = new MemoryStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = stream.Read(buffer)) != 0)
        {
            if (bytes.Length + read > maxBytes) throw new InvalidDataException("Local agent file grew beyond its size limit.");
            bytes.Write(buffer, 0, read);
        }
        return bytes.ToArray();
    }

    internal static void RejectLinks(string path)
    {
        string? current = Path.GetFullPath(path);
        while (current != null)
        {
            try
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Symlinks/reparse points are forbidden in agent security paths.");
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
            // macOS has OS-owned /var and /tmp aliases. Its existing deployment policy is separate.
            current = OperatingSystem.IsMacOS() ? null : Path.GetDirectoryName(current);
        }
    }

    internal static void AtomicWrite(string path, byte[] data, Action<string> protect)
    {
        RejectLinks(path);
        string directory = Path.GetDirectoryName(Path.GetFullPath(path))!;
        if (!Directory.Exists(directory)) throw new DirectoryNotFoundException(directory);
        string temporary = Path.Combine(directory, ".winhub-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write,
                Share = FileShare.None, Options = FileOptions.WriteThrough };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(temporary, options))
            {
                protect(temporary);
                stream.Write(data);
                stream.Flush(flushToDisk: true);
            }
            RejectLinks(path);
            File.Move(temporary, path, overwrite: true);
            protect(path);
            if (OperatingSystem.IsLinux()) FlushDirectory(directory);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static void FlushDirectory(string directory)
    {
        int fd = open(directory, 0x10000 /* O_DIRECTORY */);
        if (fd < 0) throw new IOException("Could not open state directory for durability check.");
        try { if (fsync(fd) != 0) throw new IOException("Could not flush agent state directory."); }
        finally { close(fd); }
    }
    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)] private static extern int open(string path, int flags);
    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)] private static extern int fsync(int fd);
    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)] private static extern int close(int fd);
    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)] private static extern int lchown(string path, uint owner, uint group);
    [System.Runtime.InteropServices.DllImport("libc")] private static extern uint geteuid();
    [System.Runtime.InteropServices.DllImport("libc")] private static extern uint getegid();
    [System.Runtime.InteropServices.DllImport("libc", SetLastError = true)] private static extern int kill(int processId, int signal);

    internal static void SecureUnixOwner(string path)
    {
        if (!OperatingSystem.IsWindows() && lchown(path, geteuid(), getegid()) != 0)
            throw new IOException("Could not secure ownership of agent state.");
    }

    internal static string HardwareIdentity(string path, bool existingEnrollment, Func<string> create, Action<string> protect)
    {
        RejectLinks(path);
        if (File.Exists(path))
        {
            string identity = ReadText(path, 1024).Trim();
            if (!(identity.StartsWith("WINHUB-", StringComparison.OrdinalIgnoreCase) || identity.StartsWith("HWID-FALLBACK-", StringComparison.OrdinalIgnoreCase))
                || identity.Length > 128 || identity.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
                throw new InvalidDataException("Saved hardware identity is invalid; do not re-enroll automatically. Administrator recovery is required.");
            return identity;
        }
        if (existingEnrollment) throw new InvalidDataException("Hardware identity is missing for an enrolled agent. Restore its state; automatic identity replacement is forbidden.");
        string generated = create();
        AtomicWrite(path, Encoding.UTF8.GetBytes(generated), protect);
        return generated;
    }

    internal static async Task CopyBoundedAsync(Stream source, Stream destination, long limit, CancellationToken token)
    {
        byte[] buffer = new byte[65536];
        long count = 0;
        int read;
        while ((read = await source.ReadAsync(buffer, token)) != 0)
        {
            count += read;
            if (count > limit) throw new InvalidDataException("Stream exceeded the configured byte limit.");
            await destination.WriteAsync(buffer.AsMemory(0, read), token);
        }
    }

    // Drains the pipe without retaining unlimited output; exceeding the cap cancels execution immediately.
    internal static async Task<string> CaptureAsync(StreamReader reader, int maxCharacters, CancellationTokenSource execution)
    {
        char[] buffer = new char[4096];
        var output = new StringBuilder();
        int read;
        while ((read = await reader.ReadAsync(buffer.AsMemory(), execution.Token)) != 0)
        {
            if (output.Length + read > maxCharacters)
            {
                execution.Cancel();
                throw new InvalidDataException("Task output exceeded its limit.");
            }
            output.Append(buffer, 0, read);
        }
        return output.ToString();
    }

    internal static async Task<(string Output, string Error, int ExitCode)> RunCapturedAsync(
        System.Diagnostics.ProcessStartInfo start, int timeoutSeconds, int maxCharacters, CancellationToken token)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
        if (OperatingSystem.IsLinux())
        {
            if (!File.Exists("/usr/bin/setsid") || !string.IsNullOrEmpty(start.Arguments))
                throw new InvalidDataException("Linux task execution requires /usr/bin/setsid and structured arguments.");
            var session = new System.Diagnostics.ProcessStartInfo("/usr/bin/setsid")
            {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true,
                WorkingDirectory = start.WorkingDirectory
            };
            session.ArgumentList.Add("--wait");
            session.ArgumentList.Add("--");
            session.ArgumentList.Add(start.FileName);
            foreach (string argument in start.ArgumentList) session.ArgumentList.Add(argument);
            foreach (var variable in start.Environment) session.Environment[variable.Key] = variable.Value;
            start = session;
        }
        using var process = System.Diagnostics.Process.Start(start) ?? throw new IOException("Could not start task process.");
        try
        {
            Task<string> stdout = CaptureAsync(process.StandardOutput, maxCharacters, deadline);
            Task<string> stderr = CaptureAsync(process.StandardError, maxCharacters, deadline);
            await Task.WhenAll(stdout, stderr, process.WaitForExitAsync(deadline.Token));
            return (stdout.Result, stderr.Result, process.ExitCode);
        }
        finally
        {
            // Kill the session even if its original shell exited while a descendant kept a pipe open.
            // This is cleanup, not a security sandbox for intentionally malicious root scripts.
            if (OperatingSystem.IsLinux()) kill(-process.Id, 9);
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                using var killDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                await process.WaitForExitAsync(killDeadline.Token);
            }
        }
    }
}
