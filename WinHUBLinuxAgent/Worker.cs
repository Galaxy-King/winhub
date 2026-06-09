using System.Diagnostics;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WinHUBLinuxAgent;

public record EnrollPayload(string global_token, string hw_id, string hostname, string os_version, string os_type, string agent_version, NetworkInterfaceInfo[] network_interfaces, HostInventoryInfo host_info, string previous_auth_token, string previous_hw_id, string agent_public_key_pem, string agent_key_fingerprint, string signed_at, string signed_nonce, string signature);
public record PollPayload(string hw_id, string auth_token, string agent_version, string agent_public_key_pem, string agent_key_fingerprint, string signed_at, string signed_nonce, string signature);
public record TelemetryPayload(string hw_id, string auth_token, string agent_version, double cpu, double ram, double disk_c, HostInventoryInfo? host_info, string agent_public_key_pem, string agent_key_fingerprint, string signed_at, string signed_nonce, string signature);
public record ResultPayload(string hw_id, string auth_token, string agent_version, string task_id, string status, string log, string agent_public_key_pem, string agent_key_fingerprint, string signed_at, string signed_nonce, string signature);
public record NetworkInterfaceInfo(string name, string description, string type, string status, string mac, string[] ipv4, string[] ipv6, string[] gateways, string[] dns_servers, bool dhcp_enabled, long speed_mbps);
public record VolumeInfo(string name, string label, string format, string type, long total_gb, long free_gb, bool ready);
public record BitLockerInventoryInfo(string status, int encrypted_percentage, string protection_status, string conversion_status, string raw_summary);
public record LinuxEncryptionInventoryInfo(string status, string[] methods, string root_device, string raw_summary);
public record SecurityInventoryInfo(bool pending_reboot, string firewall_domain, string firewall_private, string firewall_public, string bitlocker_summary, BitLockerInventoryInfo bitlocker, string defender_service_state, bool veracrypt_detected, bool truecrypt_detected, LinuxEncryptionInventoryInfo? linux_encryption = null);
public record HostInventoryInfo(string machine_name, string fqdn, string domain_name, string user_domain_name, bool likely_domain_joined, string os_description, string os_architecture, string process_architecture, string timezone, int processor_count, ulong total_memory_mb, long uptime_seconds, string boot_time_utc, VolumeInfo[] volumes, SecurityInventoryInfo security);
public readonly record struct PollTiming(int? NextPollAfterSeconds, int? PollJitterSeconds, int? TelemetryAfterSeconds);

public class AgentConfig
{
    public string ServerUrl { get; set; } = "https://127.0.0.1";
    public string GlobalApiKey { get; set; } = "";
    public int PollIntervalSeconds { get; set; } = 30;
    public int PollJitterSeconds { get; set; } = 30;
    public int StartupSpreadSeconds { get; set; } = 120;
    public string TaskHmacSecret { get; set; } = "";
    public int DefaultTaskTimeoutSeconds { get; set; } = 1800;
    public int MaxResultLogBytes { get; set; } = 262144;
    public bool IgnoreTlsCertificateErrors { get; set; } = false;
    public string ServerCertificateSha256 { get; set; } = "";
    public bool RequireTaskSignature { get; set; } = true;
}

public class AgentSecrets
{
    public string GlobalApiKey { get; set; } = "";
    public string TaskHmacSecret { get; set; } = "";
}

public static class AgentBuildInfo
{
    public static readonly string Version =
        typeof(AgentBuildInfo).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion
            .Split('+')[0] ?? "0.0.0";
}

[JsonSerializable(typeof(EnrollPayload))]
[JsonSerializable(typeof(PollPayload))]
[JsonSerializable(typeof(TelemetryPayload))]
[JsonSerializable(typeof(ResultPayload))]
[JsonSerializable(typeof(AgentConfig))]
[JsonSerializable(typeof(AgentSecrets))]
[JsonSerializable(typeof(NetworkInterfaceInfo))]
[JsonSerializable(typeof(NetworkInterfaceInfo[]))]
[JsonSerializable(typeof(VolumeInfo))]
[JsonSerializable(typeof(VolumeInfo[]))]
[JsonSerializable(typeof(BitLockerInventoryInfo))]
[JsonSerializable(typeof(LinuxEncryptionInventoryInfo))]
[JsonSerializable(typeof(SecurityInventoryInfo))]
[JsonSerializable(typeof(HostInventoryInfo))]
internal partial class AppJsonSerializerContext : JsonSerializerContext { }

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly HttpClient _httpClient;
    private AgentConfig _config = new();
    private bool _signatureWarningLogged;
    private readonly string ConfigDirectory = "/etc/winhub-agent";
    private readonly string DataDirectory = "/var/lib/winhub-agent";
    private readonly string UpdatesDirectory = "/var/lib/winhub-agent/updates";
    private string ConfigFilePath => Path.Combine(ConfigDirectory, "winhub_agent.conf");
    private string BootstrapConfigFilePath => Path.Combine(ConfigDirectory, "winhub_agent.bootstrap.conf");
    private string TokenFilePath => Path.Combine(DataDirectory, "agent.token");
    private string SecretsFilePath => Path.Combine(DataDirectory, "agent.secrets");
    private string HardwareIdFilePath => Path.Combine(DataDirectory, "agent.hwid");
    private string AgentIdentityKeyFilePath => Path.Combine(DataDirectory, "agent_identity.key");
    private string HardwareId = "";
    private string AuthToken = "";
    private string FriendlyOsName = "";
    private RSA? AgentIdentityKey;
    private string AgentPublicKeyPem = "";
    private string AgentKeyFingerprint = "";
    private DateTime _lastInventoryUtc = DateTime.MinValue;
    private HostInventoryInfo? _cachedHostInventory;
    private (ulong Idle, ulong Total)? _previousCpuTimes;
    private string _lastLoggedPollStatus = "";

    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = ValidateServerCertificate
        };
        _httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("WinHUB Linux Agent starting...");
        LoadConfig();
        Directory.CreateDirectory(DataDirectory);
        Directory.CreateDirectory(UpdatesDirectory);
        RestrictPath(DataDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        HardwareId = GetOrCreateHardwareId();
        EnsureAgentIdentityKey();
        FriendlyOsName = GetFriendlyOsName();
        _logger.LogInformation("Hardware ID: {HardwareId}", HardwareId);
        _logger.LogInformation("OS Detected: {Os}", FriendlyOsName);

        int telemetryIntervalSeconds = 300;
        int startupDelaySeconds = GetStableDelaySeconds("startup-poll-spread-v1", GetStartupSpreadSeconds() + 1);
        int telemetryDelaySeconds = GetStableDelaySeconds("startup-telemetry-spread-v1", telemetryIntervalSeconds + 1);
        bool tokenLoaded = LoadToken();
        if (tokenLoaded)
        {
            _logger.LogInformation("Existing agent token loaded. Polling starts immediately.");
        }
        else if (startupDelaySeconds > 0)
        {
            _logger.LogInformation("Initial enrollment startup spread delay: {Seconds}s", startupDelaySeconds);
            await Task.Delay(TimeSpan.FromSeconds(startupDelaySeconds), stoppingToken);
        }

        if (!tokenLoaded)
        {
            _logger.LogWarning("Initiating enrollment...");
            await EnrollAgentAsync(stoppingToken);
        }

        DateTime lastTelemetrySent = DateTime.UtcNow - TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(telemetryDelaySeconds);
        while (!stoppingToken.IsCancellationRequested)
        {
            if ((DateTime.UtcNow - lastTelemetrySent).TotalSeconds >= telemetryIntervalSeconds)
            {
                await SendTelemetryAsync(stoppingToken);
                lastTelemetrySent = DateTime.UtcNow;
            }

            PollTiming? timing = await PollServerAsync(stoppingToken);
            if (timing?.TelemetryAfterSeconds is int telemetryAfter)
                telemetryIntervalSeconds = ClampSeconds(telemetryAfter, 60, 86400);

            int basePoll = timing?.NextPollAfterSeconds is int nextPollAfter
                ? ClampSeconds(nextPollAfter, 10, 3600)
                : GetConfiguredPollIntervalSeconds();
            int jitter = timing?.PollJitterSeconds is int serverJitter
                ? ClampSeconds(serverJitter, 0, 3600)
                : GetPollJitterSeconds();
            await Task.Delay(TimeSpan.FromSeconds(basePoll + NextRandomDelaySeconds(0, jitter)), stoppingToken);
        }
    }

    private bool ValidateServerCertificate(HttpRequestMessage message, System.Security.Cryptography.X509Certificates.X509Certificate2? cert, System.Security.Cryptography.X509Certificates.X509Chain? chain, SslPolicyErrors errors)
    {
        if (_config.IgnoreTlsCertificateErrors) return true;
        string pinned = NormalizeThumbprint(_config.ServerCertificateSha256);
        if (!string.IsNullOrWhiteSpace(pinned) && cert != null)
        {
            string actual = NormalizeThumbprint(cert.GetCertHashString(HashAlgorithmName.SHA256));
            return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(actual), Encoding.ASCII.GetBytes(pinned));
        }
        return errors == SslPolicyErrors.None;
    }

    private void LoadConfig()
    {
        Directory.CreateDirectory(ConfigDirectory);
        if (!File.Exists(ConfigFilePath))
        {
            SaveConfig();
            _logger.LogInformation("Created default runtime config at {Path}", ConfigFilePath);
        }

        try
        {
            string json = File.ReadAllText(ConfigFilePath);
            bool needsBackfill = ConfigNeedsBackfill(json);
            var loaded = JsonSerializer.Deserialize(json, AppJsonSerializerContext.Default.AgentConfig);
            if (loaded != null) _config = loaded;
            _config.ServerUrl = (_config.ServerUrl ?? "").Trim().TrimEnd('/');
            _httpClient.Timeout = TimeSpan.FromSeconds(Math.Max(10, Math.Min(300, _config.DefaultTaskTimeoutSeconds)));
            if (needsBackfill)
            {
                SaveConfig();
                _logger.LogInformation("Runtime config backfilled with missing default keys.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError("Failed to read config file. Using defaults. Error: {Message}", ex.Message);
        }

        MigratePlaintextSecretsFromConfig();
        MigrateSecretsFromBootstrapConfig();
    }

    private void SaveConfig()
    {
        Directory.CreateDirectory(ConfigDirectory);
        File.WriteAllText(ConfigFilePath, JsonSerializer.Serialize(_config, AppJsonSerializerContext.Default.AgentConfig));
        RestrictPath(ConfigFilePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static bool ConfigNeedsBackfill(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return true;
            string[] required =
            {
                nameof(AgentConfig.ServerUrl),
                nameof(AgentConfig.GlobalApiKey),
                nameof(AgentConfig.PollIntervalSeconds),
                nameof(AgentConfig.PollJitterSeconds),
                nameof(AgentConfig.StartupSpreadSeconds),
                nameof(AgentConfig.TaskHmacSecret),
                nameof(AgentConfig.DefaultTaskTimeoutSeconds),
                nameof(AgentConfig.MaxResultLogBytes),
                nameof(AgentConfig.IgnoreTlsCertificateErrors),
                nameof(AgentConfig.ServerCertificateSha256),
                nameof(AgentConfig.RequireTaskSignature)
            };
            return required.Any(key => !doc.RootElement.TryGetProperty(key, out _));
        }
        catch
        {
            return false;
        }
    }

    private async Task EnrollAgentAsync(CancellationToken stoppingToken, string previousAuthToken = "", string previousHwId = "")
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                string enrollmentToken = GetProtectedSecret("GlobalApiKey");
                if (string.IsNullOrWhiteSpace(enrollmentToken))
                {
                    _logger.LogError("Enrollment token is missing. Put GlobalApiKey in /etc/winhub-agent/winhub_agent.bootstrap.conf, then restart.");
                    await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
                    continue;
                }

                var signature = CreateAgentSignature("/api/agent/enroll", previousAuthToken, AgentBuildInfo.Version);
                var payload = new EnrollPayload(enrollmentToken, HardwareId, Environment.MachineName, FriendlyOsName, "Linux", AgentBuildInfo.Version, GetNetworkInterfaces(), GetCachedHostInventory(true), previousAuthToken, previousHwId, AgentPublicKeyPem, AgentKeyFingerprint, signature.SignedAt, signature.Nonce, signature.Signature);
                var response = await _httpClient.PostAsync($"{_config.ServerUrl}/api/agent/enroll", JsonContent(payload), stoppingToken);
                if (response.IsSuccessStatusCode)
                {
                    using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(stoppingToken));
                    string newToken = doc.RootElement.GetProperty("auth_token").GetString() ?? "";
                    string approvalStatus = doc.RootElement.TryGetProperty("approval_status", out var approvalEl) ? approvalEl.GetString() ?? "" : "";
                    bool shouldReplaceToken = string.IsNullOrWhiteSpace(previousAuthToken) || approvalStatus.Equals("Approved", StringComparison.OrdinalIgnoreCase);
                    if (shouldReplaceToken)
                    {
                        SaveToken(newToken);
                        AuthToken = newToken;
                    }
                    _logger.LogInformation("Enrollment successful. Approval status: {Status}", approvalStatus);
                    return;
                }
                _logger.LogWarning("Enrollment failed. Server returned: {Status}", response.StatusCode);
            }
            catch (Exception ex)
            {
                _logger.LogError("Connection to server failed: {Message}", ex.Message);
            }

            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        }
    }

    private async Task<PollTiming?> PollServerAsync(CancellationToken stoppingToken)
    {
        try
        {
            var signature = CreateAgentSignature("/api/agent/poll", AuthToken, AgentBuildInfo.Version);
            var payload = new PollPayload(HardwareId, AuthToken, AgentBuildInfo.Version, AgentPublicKeyPem, AgentKeyFingerprint, signature.SignedAt, signature.Nonce, signature.Signature);
            var response = await _httpClient.PostAsync($"{_config.ServerUrl}/api/agent/poll", JsonContent(payload), stoppingToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Poll failed. Server returned: {Status}", response.StatusCode);
                if (response.StatusCode is System.Net.HttpStatusCode.Forbidden or System.Net.HttpStatusCode.Unauthorized)
                {
                    string previousAuthToken = AuthToken;
                    string previousHwId = HardwareId;
                    _logger.LogWarning("Server rejected poll token. Attempting secure re-enrollment with previous token proof.");
                    await EnrollAgentAsync(stoppingToken, previousAuthToken, previousHwId);
                }
                return null;
            }

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(stoppingToken));
            JsonElement root = doc.RootElement;
            PollTiming timing = ReadPollTiming(root);
            string status = root.GetProperty("status").GetString() ?? "";
            if (status != "task")
            {
                LogPollStatus(status);
                return timing;
            }

            string taskId = root.GetProperty("task_id").GetString() ?? "";
            string action = root.GetProperty("action").GetString() ?? "";
            _logger.LogInformation("Task received. TaskId={TaskId}, Action={Action}", taskId, action);
            int timeoutSeconds = root.TryGetProperty("timeout_seconds", out var timeoutEl) && timeoutEl.TryGetInt32(out var parsedTimeout)
                ? parsedTimeout
                : _config.DefaultTaskTimeoutSeconds;

            if (!ValidateTaskSignature(root))
            {
                _logger.LogError("Task signature verification failed. TaskId={TaskId}, Action={Action}", taskId, action);
                await ReportResultAsync(taskId, "Error", "Task signature verification failed. Task was not executed.", stoppingToken);
                return timing;
            }

            if (action == "reboot")
            {
                await ReportResultAsync(taskId, "Success", "Reboot command received...", stoppingToken);
                Process.Start(new ProcessStartInfo("/bin/systemctl", "reboot") { UseShellExecute = false });
                return timing;
            }

            if (action == "agent_update")
            {
                (string updateStatus, string updateLog) = await StageAndLaunchAgentUpdateAsync(taskId, root.GetProperty("payload"), stoppingToken);
                await ReportResultAsync(taskId, updateStatus, updateLog, stoppingToken);
                return timing;
            }

            string script = "";
            if (root.TryGetProperty("payload", out var pl) && pl.TryGetProperty("script", out var s))
                script = s.GetString() ?? "";
            (string executionStatus, string logOutput) = await ExecuteShellAsync(script, timeoutSeconds, stoppingToken);
            await ReportResultAsync(taskId, executionStatus, logOutput, stoppingToken);
            _logger.LogInformation("Task completed. TaskId={TaskId}, Status={Status}", taskId, executionStatus);
            return timing;
        }
        catch (Exception ex)
        {
            _logger.LogError("Polling failed: {Message}", ex.Message);
            return null;
        }
    }

    private void LogPollStatus(string status)
    {
        if (string.IsNullOrWhiteSpace(status)) status = "unknown";
        if (status.Equals(_lastLoggedPollStatus, StringComparison.OrdinalIgnoreCase)) return;
        _lastLoggedPollStatus = status;
        _logger.LogInformation("Poll status: {Status}", status);
    }

    private async Task SendTelemetryAsync(CancellationToken stoppingToken)
    {
        if (string.IsNullOrEmpty(AuthToken)) return;
        try
        {
            var signature = CreateAgentSignature("/api/agent/telemetry", AuthToken, AgentBuildInfo.Version);
            var payload = new TelemetryPayload(HardwareId, AuthToken, AgentBuildInfo.Version, Math.Round(GetCpuUsage(), 2), Math.Round(GetRamUsage(), 2), Math.Round(GetRootFreeGb(), 2), GetCachedHostInventory(false), AgentPublicKeyPem, AgentKeyFingerprint, signature.SignedAt, signature.Nonce, signature.Signature);
            var response = await _httpClient.PostAsync($"{_config.ServerUrl}/api/agent/telemetry", JsonContent(payload), stoppingToken);
            if (response.IsSuccessStatusCode)
                _logger.LogInformation("Telemetry sent. CPU: {Cpu}% | RAM: {Ram}% | /: {Disk} GB", payload.cpu, payload.ram, payload.disk_c);
        }
        catch (Exception ex)
        {
            _logger.LogError("Failed to collect/send telemetry: {Message}", ex.Message);
        }
    }

    private async Task<(string Status, string Log)> ExecuteShellAsync(string scriptContent, int timeoutSeconds, CancellationToken stoppingToken)
    {
        if (string.IsNullOrWhiteSpace(scriptContent)) return ("Error", "Empty script provided.");
        timeoutSeconds = Math.Clamp(timeoutSeconds, 30, 86400);
        string tempScriptFile = Path.Combine(Path.GetTempPath(), $"winhub_task_{Guid.NewGuid():N}.sh");
        try
        {
            await File.WriteAllTextAsync(tempScriptFile, "#!/usr/bin/env bash\nset -o pipefail\nexport LANG=C.UTF-8\n" + scriptContent, new UTF8Encoding(false), stoppingToken);
            RestrictPath(tempScriptFile, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            var psi = new ProcessStartInfo("/bin/bash", tempScriptFile)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            using var process = Process.Start(psi) ?? throw new InvalidOperationException("Process start failed.");
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
            Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync(timeoutCts.Token);
            Task<string> stderrTask = process.StandardError.ReadToEndAsync(timeoutCts.Token);
            try
            {
                await process.WaitForExitAsync(timeoutCts.Token);
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
            {
                TryKill(process);
                return ("Error", $"Task timeout after {timeoutSeconds} seconds. Process was terminated.");
            }

            string output = await stdoutTask;
            string error = await stderrTask;
            string log = string.IsNullOrWhiteSpace(error) ? output : $"{output}\n[ERRORS]\n{error}";
            return (process.ExitCode == 0 && string.IsNullOrWhiteSpace(error) ? "Success" : "Error", TrimResultLog(log));
        }
        catch (Exception ex)
        {
            return ("Error", $"Exception: {ex.Message}");
        }
        finally
        {
            try { File.Delete(tempScriptFile); } catch { }
        }
    }

    private async Task<(string Status, string Log)> StageAndLaunchAgentUpdateAsync(string taskId, JsonElement payload, CancellationToken stoppingToken)
    {
        try
        {
            string packageUrl = GetPayloadString(payload, "package_url");
            string expectedSha256 = NormalizeThumbprint(GetPayloadString(payload, "sha256"));
            if (string.IsNullOrWhiteSpace(packageUrl)) return ("Error", "agent_update requires payload.package_url.");
            Uri downloadUri = BuildUpdatePackageUri(packageUrl);
            Directory.CreateDirectory(UpdatesDirectory);
            string packagePath = Path.Combine(UpdatesDirectory, $"WinHUBLinuxAgent_{taskId}.tar.gz");
            using (var response = await _httpClient.GetAsync(downloadUri, HttpCompletionOption.ResponseHeadersRead, stoppingToken))
            {
                response.EnsureSuccessStatusCode();
                await using var source = await response.Content.ReadAsStreamAsync(stoppingToken);
                await using var destination = File.Create(packagePath);
                await source.CopyToAsync(destination, stoppingToken);
            }
            if (!string.IsNullOrWhiteSpace(expectedSha256))
            {
                string actualSha256 = ComputeFileSha256(packagePath);
                if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(actualSha256), Encoding.ASCII.GetBytes(expectedSha256)))
                {
                    try { File.Delete(packagePath); } catch { }
                    return ("Error", $"Downloaded package SHA256 mismatch. Expected {expectedSha256}, got {actualSha256}.");
                }
            }

            string updateScript = "/opt/winhub-linux-agent/update-linux-agent.sh";
            if (!File.Exists(updateScript)) return ("Error", $"{updateScript} was not found.");
            string launcherPath = Path.Combine(UpdatesDirectory, $"launch_update_{taskId}.sh");
            await File.WriteAllTextAsync(launcherPath, $"#!/usr/bin/env bash\nset -euo pipefail\nsleep 3\n{ShellQuote(updateScript)} --package {ShellQuote(packagePath)}\n", new UTF8Encoding(false), stoppingToken);
            RestrictPath(launcherPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Process.Start(new ProcessStartInfo("/bin/bash", launcherPath)
            {
                UseShellExecute = false,
                WorkingDirectory = "/opt/winhub-linux-agent"
            });
            return ("Success", $"Agent update package staged at {packagePath}. Detached updater launched.");
        }
        catch (Exception ex)
        {
            return ("Error", $"Agent update failed before launch: {ex.Message}");
        }
    }

    private async Task ReportResultAsync(string taskId, string status, string log, CancellationToken stoppingToken)
    {
        try
        {
            var signature = CreateAgentSignature("/api/agent/result", AuthToken, AgentBuildInfo.Version);
            var payload = new ResultPayload(HardwareId, AuthToken, AgentBuildInfo.Version, taskId, status, TrimResultLog(log), AgentPublicKeyPem, AgentKeyFingerprint, signature.SignedAt, signature.Nonce, signature.Signature);
            await _httpClient.PostAsync($"{_config.ServerUrl}/api/agent/result", JsonContent(payload), stoppingToken);
        }
        catch { }
    }

    private StringContent JsonContent<T>(T payload)
    {
        string json = payload switch
        {
            EnrollPayload v => JsonSerializer.Serialize(v, AppJsonSerializerContext.Default.EnrollPayload),
            PollPayload v => JsonSerializer.Serialize(v, AppJsonSerializerContext.Default.PollPayload),
            TelemetryPayload v => JsonSerializer.Serialize(v, AppJsonSerializerContext.Default.TelemetryPayload),
            ResultPayload v => JsonSerializer.Serialize(v, AppJsonSerializerContext.Default.ResultPayload),
            _ => throw new InvalidOperationException("Unsupported payload type.")
        };
        return new StringContent(json, Encoding.UTF8, "application/json");
    }

    private bool ValidateTaskSignature(JsonElement taskResponse)
    {
        string secret = GetProtectedSecret("TaskHmacSecret");
        string providedSignature = taskResponse.TryGetProperty("signature", out var signatureEl) ? signatureEl.GetString() ?? "" : "";
        if (string.IsNullOrWhiteSpace(secret))
        {
            if (_config.RequireTaskSignature)
            {
                _logger.LogError("TaskHmacSecret is empty and RequireTaskSignature=true. Refusing task execution.");
                return false;
            }
            if (!_signatureWarningLogged)
            {
                _logger.LogWarning("TaskHmacSecret is empty. Task signature verification is disabled.");
                _signatureWarningLogged = true;
            }
            return true;
        }
        if (string.IsNullOrWhiteSpace(providedSignature)) return !_config.RequireTaskSignature;
        string taskId = taskResponse.GetProperty("task_id").GetString() ?? "";
        string action = taskResponse.GetProperty("action").GetString() ?? "";
        JsonElement payload = taskResponse.TryGetProperty("payload", out var payloadEl) ? payloadEl : default;
        string body = CanonicalizeTaskBody(taskId, action, payload);
        string expected = Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(body))).ToLowerInvariant();
        return FixedTimeEqualsHex(expected, providedSignature.Trim().ToLowerInvariant());
    }

    private static string CanonicalizeTaskBody(string taskId, string action, JsonElement payload)
    {
        string payloadJson = payload.ValueKind == JsonValueKind.Undefined ? "{}" : CanonicalJson(payload);
        return $"{{\"action\":\"{EscapeJson(action)}\",\"payload\":{payloadJson},\"task_id\":\"{EscapeJson(taskId)}\"}}";
    }

    private static string CanonicalJson(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.Object => "{" + string.Join(",", element.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal).Select(p => $"\"{EscapeJson(p.Name)}\":{CanonicalJson(p.Value)}")) + "}",
            JsonValueKind.Array => "[" + string.Join(",", element.EnumerateArray().Select(CanonicalJson)) + "]",
            JsonValueKind.String => "\"" + EscapeJson(element.GetString() ?? "") + "\"",
            JsonValueKind.Number => element.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Null => "null",
            _ => "null"
        };
    }

    private static string EscapeJson(string value)
    {
        var builder = new StringBuilder(value.Length + 8);
        foreach (char ch in value)
        {
            switch (ch)
            {
                case '"':
                    builder.Append("\\\"");
                    break;
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '\b':
                    builder.Append("\\b");
                    break;
                case '\f':
                    builder.Append("\\f");
                    break;
                case '\n':
                    builder.Append("\\n");
                    break;
                case '\r':
                    builder.Append("\\r");
                    break;
                case '\t':
                    builder.Append("\\t");
                    break;
                default:
                    if (ch < 0x20)
                        builder.Append("\\u").Append(((int)ch).ToString("x4"));
                    else
                        builder.Append(ch);
                    break;
            }
        }
        return builder.ToString();
    }

    private HostInventoryInfo GetCachedHostInventory(bool force)
    {
        if (!force && _cachedHostInventory != null && DateTime.UtcNow - _lastInventoryUtc < TimeSpan.FromMinutes(30))
            return _cachedHostInventory;
        _cachedHostInventory = GetHostInventory();
        _lastInventoryUtc = DateTime.UtcNow;
        return _cachedHostInventory;
    }

    private HostInventoryInfo GetHostInventory()
    {
        string hostname = Environment.MachineName;
        string domain = RunCommandSnapshot("hostname", "-d", 3, 300).Trim();
        if (domain == "unavailable" || domain == "timeout") domain = "";
        string fqdn = string.IsNullOrWhiteSpace(domain) ? hostname : $"{hostname}.{domain}";
        long uptime = ReadUptimeSeconds();
        return new HostInventoryInfo(
            hostname,
            fqdn,
            domain,
            "",
            !string.IsNullOrWhiteSpace(domain),
            FriendlyOsName,
            RuntimeInformation.OSArchitecture.ToString(),
            RuntimeInformation.ProcessArchitecture.ToString(),
            TimeZoneInfo.Local.Id,
            Environment.ProcessorCount,
            (ulong)Math.Round(ReadMeminfoValueKb("MemTotal") / 1024.0),
            uptime,
            uptime > 0 ? DateTime.UtcNow.AddSeconds(-uptime).ToString("o") : "",
            GetVolumes(),
            GetSecurityInventory()
        );
    }

    private SecurityInventoryInfo GetSecurityInventory()
    {
        bool pendingReboot = File.Exists("/var/run/reboot-required") || File.Exists("/run/reboot-required");
        string firewall = DetectFirewallState();
        bool veracrypt = CommandExists("veracrypt") || Directory.Exists("/usr/share/veracrypt");
        bool truecrypt = CommandExists("truecrypt") || Directory.Exists("/usr/share/truecrypt");
        LinuxEncryptionInventoryInfo linuxEncryption = GetLinuxEncryptionInventory();
        return new SecurityInventoryInfo(
            pendingReboot,
            firewall,
            firewall,
            firewall,
            linuxEncryption.raw_summary,
            new BitLockerInventoryInfo(linuxEncryption.status, linuxEncryption.status == "encrypted" ? 100 : -1, linuxEncryption.status == "encrypted" ? "on" : "unknown", linuxEncryption.status, linuxEncryption.raw_summary),
            DetectAntivirusState(),
            veracrypt,
            truecrypt,
            linuxEncryption
        );
    }

    private VolumeInfo[] GetVolumes()
    {
        try
        {
            string[] allowedFs =
            {
                "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "reiserfs",
                "jfs", "bcachefs", "vfat", "exfat", "ntfs", "nfs", "nfs4", "cifs"
            };
            string[] excludedMountPrefixes =
            {
                "/proc", "/sys", "/dev", "/run", "/var/run", "/snap"
            };
            var mounts = File.ReadAllLines("/proc/mounts")
                .Select(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                .Where(parts => parts.Length >= 3)
                .Where(parts => allowedFs.Contains(parts[2], StringComparer.OrdinalIgnoreCase))
                .Where(parts => parts[1] == "/" || !excludedMountPrefixes.Any(prefix => parts[1].Equals(prefix, StringComparison.Ordinal) || parts[1].StartsWith(prefix + "/", StringComparison.Ordinal)))
                .GroupBy(parts => parts[1])
                .Select(g => g.First())
                .OrderBy(parts => parts[1] == "/" ? "" : parts[1], StringComparer.Ordinal)
                .Take(64)
                .ToArray();
            return mounts.Select(parts =>
            {
                try
                {
                    var drive = new DriveInfo(parts[1]);
                    return new VolumeInfo(parts[1], parts[0], parts[2], "Mount", (long)Math.Round(drive.TotalSize / 1024.0 / 1024.0 / 1024.0), (long)Math.Round(drive.AvailableFreeSpace / 1024.0 / 1024.0 / 1024.0), drive.IsReady);
                }
                catch
                {
                    return new VolumeInfo(parts[1], parts[0], parts[2], "Mount", 0, 0, false);
                }
            }).ToArray();
        }
        catch
        {
            return Array.Empty<VolumeInfo>();
        }
    }

    private static LinuxEncryptionInventoryInfo GetLinuxEncryptionInventory()
    {
        string rootDevice = GetRootDevice();
        var methods = new List<string>();
        var raw = new List<string>();

        if (!string.IsNullOrWhiteSpace(rootDevice))
            raw.Add($"root={rootDevice}");

        bool crypttabPresent = File.Exists("/etc/crypttab") && File.ReadLines("/etc/crypttab")
            .Any(line => !string.IsNullOrWhiteSpace(line) && !line.TrimStart().StartsWith("#", StringComparison.Ordinal));
        if (crypttabPresent)
        {
            methods.Add("LUKS/dm-crypt");
            raw.Add("crypttab=present");
        }

        string dmsetup = CommandExists("dmsetup") ? RunCommandSnapshot("dmsetup", "ls --target crypt", 5, 3000) : "unavailable";
        if (!string.IsNullOrWhiteSpace(dmsetup) && dmsetup != "unavailable" && dmsetup != "timeout" && !dmsetup.StartsWith("exit ", StringComparison.Ordinal))
        {
            methods.Add("dm-crypt");
            raw.Add("dmsetup=" + dmsetup.Replace("\r", "").Replace("\n", "; "));
        }

        if (rootDevice.StartsWith("/dev/mapper/", StringComparison.Ordinal) || rootDevice.StartsWith("/dev/dm-", StringComparison.Ordinal))
        {
                string cryptsetup = CommandExists("cryptsetup") ? RunCommandSnapshot("cryptsetup", $"status {Path.GetFileName(rootDevice)}", 5, 3000) : "unavailable";
            string cryptLower = cryptsetup.ToLowerInvariant();
            if (cryptLower.Contains("type:") || cryptLower.Contains("cipher:") || cryptLower.Contains("device:"))
            {
                methods.Add("LUKS/dm-crypt");
                raw.Add("cryptsetup=" + cryptsetup.Replace("\r", "").Replace("\n", "; "));
            }
            else
            {
                raw.Add("mapper_root=true");
            }
        }

        methods = methods.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        string status = methods.Count > 0 ? "encrypted" : "unknown";
        string summary = raw.Count > 0 ? string.Join(" | ", raw) : "linux encryption inventory unavailable";
        return new LinuxEncryptionInventoryInfo(status, methods.ToArray(), rootDevice, summary);
    }

    private static string GetRootDevice()
    {
        try
        {
            string? root = File.ReadLines("/proc/mounts")
                .Select(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                .FirstOrDefault(parts => parts.Length >= 2 && parts[1] == "/")?[0];
            return root ?? "";
        }
        catch
        {
            return "";
        }
    }

    private NetworkInterfaceInfo[] GetNetworkInterfaces()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(nic => nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Select(nic =>
                {
                    var props = nic.GetIPProperties();
                    return new NetworkInterfaceInfo(
                        nic.Name,
                        nic.Description,
                        nic.NetworkInterfaceType.ToString(),
                        nic.OperationalStatus.ToString(),
                        nic.GetPhysicalAddress().ToString(),
                        props.UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork).Select(a => a.Address.ToString()).ToArray(),
                        props.UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetworkV6).Select(a => a.Address.ToString()).ToArray(),
                        props.GatewayAddresses.Select(g => g.Address.ToString()).Where(v => !string.IsNullOrWhiteSpace(v)).ToArray(),
                        props.DnsAddresses.Select(d => d.ToString()).ToArray(),
                        false,
                        Math.Max(0, nic.Speed / 1000000)
                    );
                }).ToArray();
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Failed to collect network interfaces: {Message}", ex.Message);
            return Array.Empty<NetworkInterfaceInfo>();
        }
    }

    private void EnsureAgentIdentityKey()
    {
        try
        {
            Directory.CreateDirectory(DataDirectory);
            AgentIdentityKey = RSA.Create(3072);
            if (File.Exists(AgentIdentityKeyFilePath))
            {
                AgentIdentityKey.ImportPkcs8PrivateKey(File.ReadAllBytes(AgentIdentityKeyFilePath), out _);
            }
            else
            {
                File.WriteAllBytes(AgentIdentityKeyFilePath, AgentIdentityKey.ExportPkcs8PrivateKey());
                RestrictPath(AgentIdentityKeyFilePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                _logger.LogInformation("Generated agent identity key.");
            }

            byte[] publicKey = AgentIdentityKey.ExportSubjectPublicKeyInfo();
            AgentPublicKeyPem = ToPem("PUBLIC KEY", publicKey);
            AgentKeyFingerprint = Convert.ToHexString(SHA256.HashData(publicKey)).ToLowerInvariant();
            _logger.LogInformation("Agent identity key fingerprint: {Fingerprint}", AgentKeyFingerprint);
        }
        catch (Exception ex)
        {
            AgentIdentityKey = null;
            AgentPublicKeyPem = "";
            AgentKeyFingerprint = "";
            _logger.LogError("Failed to load or create agent identity key: {Message}", ex.Message);
        }
    }

    private (string SignedAt, string Nonce, string Signature) CreateAgentSignature(string path, string authToken, string agentVersion)
    {
        string signedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        string nonce = Guid.NewGuid().ToString("N");
        if (AgentIdentityKey == null) return (signedAt, nonce, "");
        string canonical = string.Join("\n", new[] { path ?? "", HardwareId ?? "", authToken ?? "", agentVersion ?? "", signedAt, nonce });
        byte[] signature = AgentIdentityKey.SignData(Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return (signedAt, nonce, Convert.ToBase64String(signature));
    }

    private string GetOrCreateHardwareId()
    {
        try
        {
            if (File.Exists(HardwareIdFilePath))
            {
                string saved = File.ReadAllText(HardwareIdFilePath).Trim();
                if (saved.StartsWith("WINHUB-", StringComparison.OrdinalIgnoreCase) || saved.StartsWith("HWID-FALLBACK-", StringComparison.OrdinalIgnoreCase))
                    return saved;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Failed to read persisted hardware ID: {Message}", ex.Message);
        }

        string generated = GeneratePersistentHardwareId();
        File.WriteAllText(HardwareIdFilePath, generated, Encoding.UTF8);
        RestrictPath(HardwareIdFilePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        return generated;
    }

    private static string GeneratePersistentHardwareId()
    {
        string machineId = ReadFirstExistingText("/etc/machine-id", "/var/lib/dbus/machine-id").Trim();
        string source = string.Join("|", new[] { "winhub-linux-agent-install-v1", Guid.NewGuid().ToString("N"), machineId, Environment.MachineName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString() });
        return "WINHUB-" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(source))).ToLowerInvariant();
    }

    private void SaveToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return;
        File.WriteAllText(TokenFilePath, token, Encoding.UTF8);
        RestrictPath(TokenFilePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private bool LoadToken()
    {
        if (!File.Exists(TokenFilePath)) return false;
        try
        {
            AuthToken = File.ReadAllText(TokenFilePath).Trim();
            return !string.IsNullOrWhiteSpace(AuthToken);
        }
        catch { return false; }
    }

    private void MigratePlaintextSecretsFromConfig()
    {
        bool changed = false;
        if (!string.IsNullOrWhiteSpace(_config.GlobalApiKey))
        {
            SaveProtectedSecret("GlobalApiKey", _config.GlobalApiKey);
            _config.GlobalApiKey = "";
            changed = true;
        }
        if (!string.IsNullOrWhiteSpace(_config.TaskHmacSecret))
        {
            SaveProtectedSecret("TaskHmacSecret", _config.TaskHmacSecret);
            _config.TaskHmacSecret = "";
            changed = true;
        }
        if (changed) SaveConfig();
    }

    private void MigrateSecretsFromBootstrapConfig()
    {
        if (!File.Exists(BootstrapConfigFilePath)) return;
        try
        {
            var bootstrap = JsonSerializer.Deserialize(File.ReadAllText(BootstrapConfigFilePath), AppJsonSerializerContext.Default.AgentConfig);
            bool migrated = false;
            if (!string.IsNullOrWhiteSpace(bootstrap?.GlobalApiKey))
            {
                SaveProtectedSecret("GlobalApiKey", bootstrap.GlobalApiKey);
                migrated = true;
            }
            if (!string.IsNullOrWhiteSpace(bootstrap?.TaskHmacSecret))
            {
                SaveProtectedSecret("TaskHmacSecret", bootstrap.TaskHmacSecret);
                migrated = true;
            }
            if (migrated) File.Delete(BootstrapConfigFilePath);
        }
        catch (Exception ex)
        {
            _logger.LogError("Failed to read bootstrap config: {Message}", ex.Message);
        }
    }

    private AgentSecrets LoadSecretStore()
    {
        if (!File.Exists(SecretsFilePath)) return new AgentSecrets();
        try
        {
            return JsonSerializer.Deserialize(File.ReadAllText(SecretsFilePath), AppJsonSerializerContext.Default.AgentSecrets) ?? new AgentSecrets();
        }
        catch (Exception ex)
        {
            _logger.LogError("Failed to read secret store: {Message}", ex.Message);
            return new AgentSecrets();
        }
    }

    private void SaveProtectedSecret(string name, string value)
    {
        var store = LoadSecretStore();
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
        if (name == "GlobalApiKey") store.GlobalApiKey = encoded;
        else if (name == "TaskHmacSecret") store.TaskHmacSecret = encoded;
        else return;
        File.WriteAllText(SecretsFilePath, JsonSerializer.Serialize(store, AppJsonSerializerContext.Default.AgentSecrets));
        RestrictPath(SecretsFilePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private string GetProtectedSecret(string name)
    {
        var store = LoadSecretStore();
        string encoded = name == "GlobalApiKey" ? store.GlobalApiKey : name == "TaskHmacSecret" ? store.TaskHmacSecret : "";
        if (string.IsNullOrWhiteSpace(encoded)) return "";
        try { return Encoding.UTF8.GetString(Convert.FromBase64String(encoded)); }
        catch { return ""; }
    }

    private string GetFriendlyOsName()
    {
        try
        {
            var values = File.ReadAllLines("/etc/os-release")
                .Select(line => line.Split('=', 2))
                .Where(parts => parts.Length == 2)
                .ToDictionary(parts => parts[0], parts => parts[1].Trim('"'));
            if (values.TryGetValue("PRETTY_NAME", out string? pretty) && !string.IsNullOrWhiteSpace(pretty))
                return pretty;
        }
        catch { }
        return RuntimeInformation.OSDescription;
    }

    private double GetCpuUsage()
    {
        var current = ReadCpuTimes();
        if (current == null) return 0;
        if (_previousCpuTimes == null)
        {
            _previousCpuTimes = current;
            return 0;
        }
        ulong idleDiff = current.Value.Idle - _previousCpuTimes.Value.Idle;
        ulong totalDiff = current.Value.Total - _previousCpuTimes.Value.Total;
        _previousCpuTimes = current;
        return totalDiff == 0 ? 0 : Math.Max(0, Math.Min(100, (totalDiff - idleDiff) * 100.0 / totalDiff));
    }

    private static (ulong Idle, ulong Total)? ReadCpuTimes()
    {
        try
        {
            string[] parts = File.ReadLines("/proc/stat").First().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            ulong[] values = parts.Skip(1).Select(ulong.Parse).ToArray();
            ulong idle = values.Length > 4 ? values[3] + values[4] : values[3];
            ulong total = values.Aggregate(0UL, (a, b) => a + b);
            return (idle, total);
        }
        catch { return null; }
    }

    private static double GetRamUsage()
    {
        double total = ReadMeminfoValueKb("MemTotal");
        double available = ReadMeminfoValueKb("MemAvailable");
        return total <= 0 ? 0 : (total - available) * 100.0 / total;
    }

    private static double GetRootFreeGb()
    {
        try
        {
            var drive = new DriveInfo("/");
            return drive.AvailableFreeSpace / 1024.0 / 1024.0 / 1024.0;
        }
        catch { return 0; }
    }

    private static double ReadMeminfoValueKb(string key)
    {
        try
        {
            string? line = File.ReadLines("/proc/meminfo").FirstOrDefault(l => l.StartsWith(key + ":", StringComparison.Ordinal));
            if (line == null) return 0;
            string digits = new(line.Where(ch => char.IsDigit(ch)).ToArray());
            return double.TryParse(digits, out double value) ? value : 0;
        }
        catch { return 0; }
    }

    private static long ReadUptimeSeconds()
    {
        try
        {
            string first = File.ReadAllText("/proc/uptime").Split(' ', StringSplitOptions.RemoveEmptyEntries)[0];
            return (long)double.Parse(first, System.Globalization.CultureInfo.InvariantCulture);
        }
        catch { return 0; }
    }

    private static string DetectFirewallState()
    {
        if (CommandExists("ufw"))
        {
            string ufw = RunCommandSnapshot("ufw", "status", 4, 1000).ToLowerInvariant();
            if (ufw.Contains("status: active")) return "enabled";
            if (ufw.Contains("status: inactive")) return "disabled";
        }
        if (CommandExists("firewall-cmd"))
        {
            string firewalld = RunCommandSnapshot("firewall-cmd", "--state", 4, 1000).ToLowerInvariant();
            if (firewalld.Contains("running")) return "enabled";
        }
        return "unknown";
    }

    private static string DetectAntivirusState()
    {
        if (CommandExists("clamdscan") || CommandExists("clamscan")) return "clamav_installed";
        return "unknown";
    }

    private static bool CommandExists(string command)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("/bin/sh", $"-c \"command -v {ShellQuote(command)} >/dev/null 2>&1\"") { UseShellExecute = false });
            process?.WaitForExit(3000);
            return process?.ExitCode == 0;
        }
        catch { return false; }
    }

    private static string RunCommandSnapshot(string fileName, string arguments, int timeoutSeconds, int maxChars)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo(fileName, arguments)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            });
            if (process == null) return "unavailable";
            string output = "";
            string error = "";
            Task stdout = Task.Run(async () => output = await process.StandardOutput.ReadToEndAsync());
            Task stderr = Task.Run(async () => error = await process.StandardError.ReadToEndAsync());
            if (!process.WaitForExit(timeoutSeconds * 1000))
            {
                TryKill(process);
                return "timeout";
            }
            Task.WaitAll(stdout, stderr);
            string combined = (output + "\n" + error).Trim();
            if (string.IsNullOrWhiteSpace(combined)) return process.ExitCode == 0 ? "ok" : $"exit {process.ExitCode}";
            return combined.Length > maxChars ? combined[..maxChars] + "\n[truncated]" : combined;
        }
        catch { return "unavailable"; }
    }

    private static string ReadFirstExistingText(params string[] paths)
    {
        foreach (string path in paths)
        {
            try
            {
                if (File.Exists(path)) return File.ReadAllText(path);
            }
            catch { }
        }
        return "";
    }

    private int GetConfiguredPollIntervalSeconds() => ClampSeconds(_config.PollIntervalSeconds, 10, 3600);
    private int GetPollJitterSeconds() => ClampSeconds(_config.PollJitterSeconds, 0, 3600);
    private int GetStartupSpreadSeconds() => ClampSeconds(_config.StartupSpreadSeconds, 0, 3600);
    private static int ClampSeconds(int value, int min, int max) => Math.Max(min, Math.Min(max, value));
    private int GetStableDelaySeconds(string purpose, int maxExclusive)
    {
        if (maxExclusive <= 1) return 0;
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes($"{HardwareId}|{Environment.MachineName}|{purpose}"));
        return (int)(BitConverter.ToUInt32(hash, 0) % (uint)maxExclusive);
    }
    private static int NextRandomDelaySeconds(int minInclusive, int maxInclusive) => maxInclusive <= minInclusive ? minInclusive : RandomNumberGenerator.GetInt32(minInclusive, maxInclusive + 1);
    private static PollTiming ReadPollTiming(JsonElement root) => new(TryGetJsonInt(root, "next_poll_after"), TryGetJsonInt(root, "poll_jitter_seconds"), TryGetJsonInt(root, "telemetry_after"));
    private static int? TryGetJsonInt(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var value)) return null;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int number)) return number;
        if (value.ValueKind == JsonValueKind.String && int.TryParse(value.GetString(), out number)) return number;
        return null;
    }
    private Uri BuildUpdatePackageUri(string packageUrl) => Uri.TryCreate(packageUrl, UriKind.Absolute, out var absolute) ? absolute : new Uri(new Uri(_config.ServerUrl.TrimEnd('/') + "/"), packageUrl.TrimStart('/'));
    private static string GetPayloadString(JsonElement payload, string name) => payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty(name, out var value) ? value.GetString() ?? "" : "";
    private static string ComputeFileSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream)).ToUpperInvariant();
    }
    private string TrimResultLog(string log)
    {
        int maxBytes = Math.Max(4096, _config.MaxResultLogBytes);
        byte[] raw = Encoding.UTF8.GetBytes(log ?? "");
        if (raw.Length <= maxBytes) return log ?? "";
        return Encoding.UTF8.GetString(raw.Take(maxBytes).ToArray()) + $"\n\n[WinHUB Linux Agent] Result log truncated to {maxBytes} bytes.";
    }
    private static string NormalizeThumbprint(string value) => new((value ?? "").Where(Uri.IsHexDigit).Select(char.ToUpperInvariant).ToArray());
    private static bool FixedTimeEqualsHex(string left, string right)
    {
        if (left.Length != right.Length) return false;
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(left), Encoding.ASCII.GetBytes(right));
    }
    private static string ToPem(string label, byte[] derBytes)
    {
        string body = Convert.ToBase64String(derBytes);
        var lines = Enumerable.Range(0, (body.Length + 63) / 64).Select(i => body.Substring(i * 64, Math.Min(64, body.Length - i * 64)));
        return $"-----BEGIN {label}-----\n{string.Join("\n", lines)}\n-----END {label}-----";
    }
    private static string ShellQuote(string value) => "'" + value.Replace("'", "'\"'\"'") + "'";
    private static void TryKill(Process process)
    {
        try { process.Kill(entireProcessTree: true); } catch { }
    }
    private static void RestrictPath(string path, UnixFileMode mode)
    {
        try
        {
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, mode);
        }
        catch { }
    }
}
