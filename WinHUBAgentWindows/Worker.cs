using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.Versioning;
using Microsoft.Win32;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using WinHUB.Security;

namespace WinHUBAgent
{
    // --- МОДЕЛІ ДАНИХ ---
    public record EnrollPayload(string global_token, string hw_id, string hostname, string os_version, string os_type, string agent_version, NetworkInterfaceInfo[] network_interfaces, HostInventoryInfo host_info, string previous_auth_token, string previous_hw_id, string agent_public_key_pem, string agent_key_fingerprint, string body_hash, string signed_at, string signed_nonce, string signature);
    public record PollPayload(string hw_id, string auth_token, string agent_version, string agent_public_key_pem, string agent_key_fingerprint, string task_signature_capabilities, string body_hash, string signed_at, string signed_nonce, string signature);
    public record TelemetryPayload(string hw_id, string auth_token, string agent_version, double cpu, double ram, double disk_c, HostInventoryInfo? host_info, string agent_public_key_pem, string agent_key_fingerprint, string body_hash, string signed_at, string signed_nonce, string signature);
    public record ResultPayload(string hw_id, string auth_token, string agent_version, string task_id, string status, string log, string agent_public_key_pem, string agent_key_fingerprint, string task_signature_v2_key_id, long task_signature_v2_sequence, string body_hash, string signed_at, string signed_nonce, string signature);
    public record NetworkInterfaceInfo(string name, string description, string type, string status, string mac, string[] ipv4, string[] ipv6, string[] gateways, string[] dns_servers, bool dhcp_enabled, long speed_mbps);
    public record VolumeInfo(string name, string label, string format, string type, long total_gb, long free_gb, bool ready);
    public record BitLockerInventoryInfo(string status, int encrypted_percentage, string protection_status, string conversion_status, string raw_summary);
    public record SecurityInventoryInfo(bool pending_reboot, string firewall_domain, string firewall_private, string firewall_public, string bitlocker_summary, BitLockerInventoryInfo bitlocker, string defender_service_state, bool veracrypt_detected, bool truecrypt_detected);
    public record HostInventoryInfo(string machine_name, string fqdn, string domain_name, string user_domain_name, bool likely_domain_joined, string os_description, string os_architecture, string process_architecture, string timezone, int processor_count, ulong total_memory_mb, long uptime_seconds, string boot_time_utc, VolumeInfo[] volumes, SecurityInventoryInfo security);
    public readonly record struct PollTiming(int? NextPollAfterSeconds, int? PollJitterSeconds, int? TelemetryAfterSeconds);

    // НОВЕ: Модель для конфігурації
    public class AgentConfig
    {
        public string ServerUrl { get; set; } = "https://192.168.37.223:8443";
        public string GlobalApiKey { get; set; } = "";
        public int PollIntervalSeconds { get; set; } = 30;
        public int PollJitterSeconds { get; set; } = 30;
        public int StartupSpreadSeconds { get; set; } = 120;
        public string TaskHmacSecret { get; set; } = "";
        public int DefaultTaskTimeoutSeconds { get; set; } = 1800;
        public int MaxResultLogBytes { get; set; } = 262144;
        public bool IgnoreTlsCertificateErrors { get; set; } = false;
        public string ServerCertificateSha256 { get; set; } = "";
        public string ServerCertificateSha256Next { get; set; } = "";
        public bool RequireTaskSignature { get; set; } = true;
        public string TaskSigningPublicKeyPem { get; set; } = "";
        public string TaskSigningKeyId { get; set; } = "";
        public long TaskSigningLastSequence { get; set; } = 0;
        public int RestartAfterConsecutivePollFailures { get; set; } = 10;
    }

    public class AgentSecrets
    {
        public string GlobalApiKey { get; set; } = "";
        public string TaskHmacSecret { get; set; } = "";
    }

    public class TaskSigningState
    {
        public string TaskSigningPublicKeyPem { get; set; } = "";
        public string TaskSigningKeyId { get; set; } = "";
        public long TaskSigningLastSequence { get; set; }
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
    [JsonSerializable(typeof(AgentConfig))] // Додано для конфігу
    [JsonSerializable(typeof(AgentSecrets))]
    [JsonSerializable(typeof(TaskSigningState))]
    [JsonSerializable(typeof(string))]
    [JsonSerializable(typeof(NetworkInterfaceInfo))]
    [JsonSerializable(typeof(NetworkInterfaceInfo[]))]
    [JsonSerializable(typeof(VolumeInfo))]
    [JsonSerializable(typeof(VolumeInfo[]))]
    [JsonSerializable(typeof(SecurityInventoryInfo))]
    [JsonSerializable(typeof(HostInventoryInfo))]
    internal partial class AppJsonSerializerContext : JsonSerializerContext { }

    [SupportedOSPlatform("windows")]
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly HttpClient _httpClient;

        // НОВЕ: Змінна для збереження конфігурації
        private AgentConfig _config = new AgentConfig();
        private readonly string ConfigFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "winhub_agent.conf");
        private readonly string BootstrapConfigFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "winhub_agent.bootstrap.conf");

        private readonly string DataDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WinHUB");
        private readonly string TokenFilePath;
        private readonly string SecretsFilePath;
        private readonly string UpdatesDirectory;
        private readonly string HardwareIdFilePath;
        private readonly string AgentIdentityKeyFilePath;
        private readonly string LogsDirectory;
        private string TaskSigningStateFilePath => Path.Combine(DataDirectory, "task-signing-state.json");
        private ExecutionJournal? _executionJournal;
        private bool _executionPersistenceFault;
        private string HardwareId = string.Empty;
        private string AuthToken = string.Empty;
        private string FriendlyOsName = string.Empty;
        private RSA? AgentIdentityKey;
        private string AgentPublicKeyPem = string.Empty;
        private string AgentKeyFingerprint = string.Empty;
        private DateTime _lastInventoryUtc = DateTime.MinValue;
        private HostInventoryInfo? _cachedHostInventory;

        private ulong _prevSystemTime = 0;
        private ulong _prevIdleTime = 0;

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
            public ulong ToULong() => ((ulong)dwHighDateTime << 32) | dwLowDateTime;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetSystemTimes(out FILETIME lpIdleTime, out FILETIME lpKernelTime, out FILETIME lpUserTime);

        [DllImport("kernel32.dll")]
        private static extern uint GetOEMCP();

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
            TokenFilePath = Path.Combine(DataDirectory, "agent.token");
            SecretsFilePath = Path.Combine(DataDirectory, "agent.secrets");
            UpdatesDirectory = Path.Combine(DataDirectory, "updates");
            HardwareIdFilePath = Path.Combine(DataDirectory, "agent.hwid");
            AgentIdentityKeyFilePath = Path.Combine(DataDirectory, "agent_identity.key");
            LogsDirectory = Path.Combine(DataDirectory, "logs");

            var handler = new HttpClientHandler
            {
                SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                AllowAutoRedirect = false,
                UseProxy = false,
                UseCookies = false,
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
                    ProductionSecurity.CertificateMatches(cert, _config.ServerCertificateSha256, _config.ServerCertificateSha256Next)
            };
            _httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30), MaxResponseContentBufferSize = ProductionSecurity.MaxApiResponseBytes };
        }

        // НОВЕ: Метод для завантаження конфігурації
        private void LoadConfig()
        {
            ValidateConfigFile(ConfigFilePath);
            if (File.Exists(ConfigFilePath))
            {
                try
                {
                    string json = ProductionSecurity.ReadText(ConfigFilePath);
                    bool needsBackfill = ConfigNeedsBackfill(json);
                    var loadedConfig = JsonSerializer.Deserialize(json, AppJsonSerializerContext.Default.AgentConfig);
                    if (loadedConfig != null) _config = loadedConfig;
                    _config.ServerUrl = (_config.ServerUrl ?? "").Trim().TrimEnd('/');
                    _httpClient.Timeout = TimeSpan.FromSeconds(Math.Max(10, Math.Min(300, _config.DefaultTaskTimeoutSeconds)));
                    if (needsBackfill)
                    {
                        SaveConfig();
                        _logger.LogInformation("Runtime config backfilled with missing default keys.");
                    }
                    _logger.LogInformation($"Runtime config loaded. Server: {_config.ServerUrl}");
                    MigratePlaintextSecretsFromConfig();
                    MigrateSecretsFromBootstrapConfig();
                    LoadTaskSigningState();
                }
                catch (Exception ex)
                {
                    throw new InvalidDataException("Could not load secure agent configuration/state. Execution is disabled.", ex);
                }
            }
            else
            {
                // Створюємо файл зі стандартними налаштуваннями, якщо його немає
                try
                {
                    string json = JsonSerializer.Serialize(_config, AppJsonSerializerContext.Default.AgentConfig);
                    File.WriteAllText(ConfigFilePath, json);
                    HardenFileAcl(ConfigFilePath);
                    _logger.LogInformation($"Created default config at {ConfigFilePath}");
                    MigrateSecretsFromBootstrapConfig();
                }
                catch (Exception ex)
                {
                    _logger.LogWarning($"Could not create default config file: {ex.Message}");
                }
            }
        }

        public static void ValidateConfigFile(string path)
        {
            AgentConfig config = JsonSerializer.Deserialize(ProductionSecurity.ReadText(path), AppJsonSerializerContext.Default.AgentConfig)
                ?? throw new InvalidDataException("Agent configuration is empty.");
            ProductionSecurity.ValidateConfiguration(config.ServerUrl, config.ServerCertificateSha256,
                config.ServerCertificateSha256Next, config.IgnoreTlsCertificateErrors, config.RequireTaskSignature);
        }

        private void LoadTaskSigningState()
        {
            TaskSigningState state;
            if (File.Exists(TaskSigningStateFilePath))
            {
                state = JsonSerializer.Deserialize(ProductionSecurity.ReadText(TaskSigningStateFilePath), AppJsonSerializerContext.Default.TaskSigningState)
                    ?? throw new InvalidDataException("Invalid task signing state.");
                if (!string.IsNullOrWhiteSpace(_config.TaskSigningKeyId) && _config.TaskSigningKeyId != state.TaskSigningKeyId)
                    throw new InvalidDataException("Config and protected task signing state use different keys.");
                state.TaskSigningLastSequence = Math.Max(state.TaskSigningLastSequence, _config.TaskSigningLastSequence);
            }
            else if (!string.IsNullOrWhiteSpace(_config.TaskSigningPublicKeyPem))
                state = new TaskSigningState { TaskSigningPublicKeyPem = _config.TaskSigningPublicKeyPem,
                    TaskSigningKeyId = _config.TaskSigningKeyId, TaskSigningLastSequence = _config.TaskSigningLastSequence };
            else
            {
                if (_config.TaskSigningLastSequence != 0 || !string.IsNullOrWhiteSpace(_config.TaskSigningKeyId))
                    throw new InvalidDataException("Incomplete task signing state. Administrator recovery is required.");
                return;
            }
            using var key = RSA.Create();
            key.ImportFromPem(state.TaskSigningPublicKeyPem);
            string keyId = Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
            if (key.KeySize < 3072 || keyId != state.TaskSigningKeyId || state.TaskSigningLastSequence <= 0)
                throw new InvalidDataException("Invalid task signing state key or sequence.");
            _config.TaskSigningPublicKeyPem = state.TaskSigningPublicKeyPem;
            _config.TaskSigningKeyId = state.TaskSigningKeyId;
            _config.TaskSigningLastSequence = state.TaskSigningLastSequence;
            SaveTaskSigningState();
        }

        private void SaveTaskSigningState()
        {
            var state = new TaskSigningState { TaskSigningPublicKeyPem = _config.TaskSigningPublicKeyPem,
                TaskSigningKeyId = _config.TaskSigningKeyId, TaskSigningLastSequence = _config.TaskSigningLastSequence };
            ProductionSecurity.AtomicWrite(TaskSigningStateFilePath,
                JsonSerializer.SerializeToUtf8Bytes(state, AppJsonSerializerContext.Default.TaskSigningState), HardenFileAcl);
        }

        // НОВЕ: Отримання людської назви ОС з Реєстру
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
                    nameof(AgentConfig.RequireTaskSignature),
                    nameof(AgentConfig.TaskSigningPublicKeyPem),
                    nameof(AgentConfig.TaskSigningKeyId),
                    nameof(AgentConfig.TaskSigningLastSequence),
                    nameof(AgentConfig.RestartAfterConsecutivePollFailures)
                };
                return required.Any(key => !doc.RootElement.TryGetProperty(key, out _));
            }
            catch
            {
                return false;
            }
        }

        private string GetFriendlyOsName()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                if (key != null)
                {
                    var productName = key.GetValue("ProductName")?.ToString();
                    var displayVersion = key.GetValue("DisplayVersion")?.ToString(); // e.g. 22H2

                    if (!string.IsNullOrEmpty(productName))
                    {
                        if (!string.IsNullOrEmpty(displayVersion))
                            return $"{productName} ({displayVersion})";
                        return productName;
                    }
                }
            }
            catch { }
            // Фолбек на старий метод, якщо немає доступу до реєстру
            return Environment.OSVersion.VersionString;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            // Завантажуємо налаштування з файлу
            EnsureLocalFileSecurity();
            _logger.LogInformation("WinHUB Agent Service starting...");
            LoadConfig();
            RemoveProtectedSecret("TaskHmacSecret");

            HardwareId = GetOrCreateHardwareId();
            EnsureAgentIdentityKey();
            _executionJournal = new ExecutionJournal(Path.Combine(DataDirectory, "execution-journal"), HardwareId, HardenFileAcl, HardenDirectoryAcl);
            _executionJournal.RecoverInterrupted();
            FriendlyOsName = GetFriendlyOsName();

            _logger.LogInformation($"Hardware ID: {HardwareId}");
            _logger.LogInformation($"OS Detected: {FriendlyOsName}");

            int pollIntervalSeconds = GetConfiguredPollIntervalSeconds();
            int pollJitterSeconds = GetPollJitterSeconds();
            int telemetryIntervalSeconds = 300;
            int startupSpreadSeconds = GetStartupSpreadSeconds();
            int restartAfterPollFailures = GetRestartAfterConsecutivePollFailures();
            int startupDelaySeconds = GetStableDelaySeconds("startup-poll-spread-v1", startupSpreadSeconds + 1);
            int telemetryDelaySeconds = GetStableDelaySeconds("startup-telemetry-spread-v1", telemetryIntervalSeconds + 1);
            int consecutivePollFailures = 0;

            _logger.LogInformation(
                $"Polling cadence: base={pollIntervalSeconds}s, jitter=0-{pollJitterSeconds}s, startup_spread=0-{startupSpreadSeconds}s, startup_delay={startupDelaySeconds}s, restart_after_failures={restartAfterPollFailures}"
            );

            if (startupDelaySeconds > 0)
            {
                await Task.Delay(TimeSpan.FromSeconds(startupDelaySeconds), stoppingToken);
            }

            if (!LoadToken())
            {
                _logger.LogWarning("Initiating Enrollment...");
                await EnrollAgentAsync(stoppingToken);
            }
            else RemoveProtectedSecret("GlobalApiKey");

            DateTime lastTelemetrySent = DateTime.UtcNow - TimeSpan.FromMinutes(5) + TimeSpan.FromSeconds(telemetryDelaySeconds);

            while (!stoppingToken.IsCancellationRequested)
            {
                await FlushJournalResultsAsync(stoppingToken);
                if ((DateTime.UtcNow - lastTelemetrySent).TotalSeconds >= telemetryIntervalSeconds)
                {
                    await SendTelemetryAsync(stoppingToken);
                    lastTelemetrySent = DateTime.UtcNow;
                }

                PollTiming? serverTiming = await PollServerAsync(stoppingToken);
                if (serverTiming.HasValue)
                {
                    if (consecutivePollFailures > 0)
                    {
                        _logger.LogInformation($"Poll recovered after {consecutivePollFailures} consecutive failure(s).");
                    }
                    consecutivePollFailures = 0;
                }
                else
                {
                    consecutivePollFailures++;
                    if (restartAfterPollFailures > 0 && consecutivePollFailures >= restartAfterPollFailures)
                    {
                        RestartThroughServiceRecovery(consecutivePollFailures);
                    }
                    if (restartAfterPollFailures > 0)
                    {
                        _logger.LogWarning($"Poll failure streak: {consecutivePollFailures}/{restartAfterPollFailures}.");
                    }
                    else
                    {
                        _logger.LogWarning($"Poll failure streak: {consecutivePollFailures}. Automatic recovery restart is disabled.");
                    }
                }

                if (serverTiming?.TelemetryAfterSeconds is int telemetryAfter)
                {
                    telemetryIntervalSeconds = ClampSeconds(telemetryAfter, 60, 86400);
                }

                int basePoll = serverTiming?.NextPollAfterSeconds is int nextPollAfter
                    ? ClampSeconds(nextPollAfter, 10, 3600)
                    : pollIntervalSeconds;
                int activeJitter = serverTiming?.PollJitterSeconds is int serverJitter
                    ? ClampSeconds(serverJitter, 0, 3600)
                    : pollJitterSeconds;
                int nextPoll = basePoll + NextRandomDelaySeconds(0, activeJitter);
                await Task.Delay(TimeSpan.FromSeconds(nextPoll), stoppingToken);
            }
        }

        private int GetConfiguredPollIntervalSeconds()
        {
            return Math.Max(10, Math.Min(3600, _config.PollIntervalSeconds));
        }

        private int GetPollJitterSeconds()
        {
            return Math.Max(0, Math.Min(3600, _config.PollJitterSeconds));
        }

        private int GetStartupSpreadSeconds()
        {
            return Math.Max(0, Math.Min(3600, _config.StartupSpreadSeconds));
        }

        private int GetRestartAfterConsecutivePollFailures()
        {
            return Math.Max(0, Math.Min(1000, _config.RestartAfterConsecutivePollFailures));
        }

        private void RestartThroughServiceRecovery(int failureCount)
        {
            _logger.LogCritical($"Poll failed {failureCount} consecutive times. Exiting with code 1 so Windows Service Recovery can restart WinHUBAgent.");
            Environment.Exit(1);
        }

        private static int ClampSeconds(int value, int min, int max)
        {
            return Math.Max(min, Math.Min(max, value));
        }

        private int GetStableDelaySeconds(string purpose, int maxExclusive)
        {
            if (maxExclusive <= 1) return 0;

            string seed = $"{HardwareId}|{Environment.MachineName}|{purpose}";
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(seed));
            uint value = BitConverter.ToUInt32(hash, 0);
            return (int)(value % (uint)maxExclusive);
        }

        private static int NextRandomDelaySeconds(int minInclusive, int maxInclusive)
        {
            if (maxInclusive <= minInclusive) return minInclusive;
            return RandomNumberGenerator.GetInt32(minInclusive, maxInclusive + 1);
        }

        private float GetCpuUsage()
        {
            if (!GetSystemTimes(out var idle, out var kernel, out var user)) return 0;

            ulong sys = kernel.ToULong() + user.ToULong();
            ulong idl = idle.ToULong();

            if (_prevSystemTime == 0)
            {
                _prevSystemTime = sys;
                _prevIdleTime = idl;
                return 0;
            }

            ulong sysDiff = sys - _prevSystemTime;
            ulong idlDiff = idl - _prevIdleTime;

            _prevSystemTime = sys;
            _prevIdleTime = idl;

            if (sysDiff == 0) return 0;
            return (float)((sysDiff - idlDiff) * 100.0 / sysDiff);
        }

        private async Task SendTelemetryAsync(CancellationToken stoppingToken)
        {
            if (string.IsNullOrEmpty(AuthToken)) return;

            try
            {
                float cpuUsage = GetCpuUsage();
                float ramUsage = 0;

                MEMORYSTATUSEX memStatus = new MEMORYSTATUSEX();
                memStatus.dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>();
                if (GlobalMemoryStatusEx(ref memStatus))
                {
                    ulong total = memStatus.ullTotalPhys;
                    ulong free = memStatus.ullAvailPhys;
                    ramUsage = (float)Math.Round(((total - free) / (double)total) * 100, 2);
                }

                float diskCFree = 0;
                var drive = DriveInfo.GetDrives().FirstOrDefault(d => d.Name.StartsWith("C", StringComparison.OrdinalIgnoreCase) && d.IsReady);
                if (drive != null) diskCFree = (float)Math.Round(drive.AvailableFreeSpace / (1024.0 * 1024.0 * 1024.0), 2);

                var unsignedPayload = new TelemetryPayload(HardwareId, AuthToken, AgentBuildInfo.Version, Math.Round(cpuUsage, 2), ramUsage, diskCFree, GetCachedHostInventory(false), AgentPublicKeyPem, AgentKeyFingerprint, "", "", "", "");
                string unsignedJson = JsonSerializer.Serialize(unsignedPayload, AppJsonSerializerContext.Default.TelemetryPayload);
                string bodyHash = ComputeAgentBodyHash(unsignedJson);
                var signature = CreateAgentSignature("/api/agent/telemetry", AuthToken, AgentBuildInfo.Version, bodyHash);
                var payload = unsignedPayload with { body_hash = bodyHash, signed_at = signature.SignedAt, signed_nonce = signature.Nonce, signature = signature.Signature };
                string jsonString = JsonSerializer.Serialize(payload, AppJsonSerializerContext.Default.TelemetryPayload);
                var content = new StringContent(jsonString, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync($"{_config.ServerUrl}/api/agent/telemetry", content, stoppingToken);

                if (response.IsSuccessStatusCode)
                    _logger.LogInformation($"Telemetry sent. CPU: {payload.cpu}% | RAM: {payload.ram}% | C: {payload.disk_c} GB");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to collect/send telemetry: {ex.Message}");
            }
        }

        private async Task EnrollAgentAsync(CancellationToken stoppingToken, string previousAuthToken = "", string previousHwId = "")
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    // Передаємо правильну назву ОС (FriendlyOsName)
                    string enrollmentToken = GetProtectedSecret("GlobalApiKey");
                    if (string.IsNullOrWhiteSpace(enrollmentToken))
                    {
                        _logger.LogError("Enrollment token is missing. Put GlobalApiKey in winhub_agent.bootstrap.conf for first bootstrap, then restart the service.");
                        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
                        continue;
                    }
                    var unsignedPayload = new EnrollPayload(enrollmentToken, HardwareId, Environment.MachineName, FriendlyOsName, "Windows", AgentBuildInfo.Version, GetNetworkInterfaces(), GetCachedHostInventory(true), previousAuthToken, previousHwId, AgentPublicKeyPem, AgentKeyFingerprint, "", "", "", "");
                    string unsignedJson = JsonSerializer.Serialize(unsignedPayload, AppJsonSerializerContext.Default.EnrollPayload);
                    string bodyHash = ComputeAgentBodyHash(unsignedJson);
                    var signature = CreateAgentSignature("/api/agent/enroll", previousAuthToken, AgentBuildInfo.Version, bodyHash);
                    var payload = unsignedPayload with { body_hash = bodyHash, signed_at = signature.SignedAt, signed_nonce = signature.Nonce, signature = signature.Signature };
                    string jsonString = JsonSerializer.Serialize(payload, AppJsonSerializerContext.Default.EnrollPayload);

                    var content = new StringContent(jsonString, Encoding.UTF8, "application/json");
                    var response = await _httpClient.PostAsync($"{_config.ServerUrl}/api/agent/enroll", content, stoppingToken);

                    if (response.IsSuccessStatusCode)
                    {
                        var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                        string newToken = result.RootElement.GetProperty("auth_token").GetString() ?? "";
                        string approvalStatus = result.RootElement.TryGetProperty("approval_status", out var approvalEl)
                            ? approvalEl.GetString() ?? ""
                            : "";
                        bool hasPreviousTokenProof = !string.IsNullOrWhiteSpace(previousAuthToken);
                        bool shouldReplaceToken = !hasPreviousTokenProof || approvalStatus.Equals("Approved", StringComparison.OrdinalIgnoreCase);

                        if (shouldReplaceToken)
                        {
                            SaveToken(newToken);
                            AuthToken = newToken;
                        }
                        else
                        {
                            _logger.LogWarning($"Enrollment returned {approvalStatus}. Preserving previous approved token for future identity proof.");
                        }

                        RemoveProtectedSecret("GlobalApiKey");
                        _logger.LogInformation($"Enrollment successful. Approval status: {approvalStatus}.");
                        break;
                    }
                    else
                    {
                        _logger.LogWarning($"Enrollment failed. Server returned: {response.StatusCode}");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Connection to server failed: {ex.Message}");
                }

                await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
            }
        }

        private async Task<PollTiming?> PollServerAsync(CancellationToken stoppingToken)
        {
            try
            {
                if (_executionPersistenceFault) throw new IOException("Execution journal persistence failed. No more tasks will run until administrator recovery and service restart.");
                var unsignedPayload = new PollPayload(HardwareId, AuthToken, AgentBuildInfo.Version, AgentPublicKeyPem, AgentKeyFingerprint, "rsa-pss-sha256-v2", "", "", "", "");
                string unsignedJson = JsonSerializer.Serialize(unsignedPayload, AppJsonSerializerContext.Default.PollPayload);
                string bodyHash = ComputeAgentBodyHash(unsignedJson);
                var signature = CreateAgentSignature("/api/agent/poll", AuthToken, AgentBuildInfo.Version, bodyHash);
                var payload = unsignedPayload with { body_hash = bodyHash, signed_at = signature.SignedAt, signed_nonce = signature.Nonce, signature = signature.Signature };
                string jsonString = JsonSerializer.Serialize(payload, AppJsonSerializerContext.Default.PollPayload);
                var content = new StringContent(jsonString, Encoding.UTF8, "application/json");

                using var response = await _httpClient.PostAsync($"{_config.ServerUrl}/api/agent/poll", content, stoppingToken);
                if (!response.IsSuccessStatusCode)
                {
                    string serverMessage = await ReadServerErrorMessageAsync(response, stoppingToken);
                    if (response.StatusCode == System.Net.HttpStatusCode.Forbidden || response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        if (IsClockSkewSignatureFailure(serverMessage))
                        {
                            _logger.LogWarning($"Server rejected poll signature as {serverMessage}. Waiting for system time to recover before retrying.");
                            return null;
                        }

                        string previousAuthToken = AuthToken;
                        string previousHwId = HardwareId;
                        _logger.LogWarning($"Server rejected poll token ({serverMessage}). Attempting secure re-enrollment with previous token proof.");
                        await EnrollAgentAsync(stoppingToken, previousAuthToken, previousHwId);
                    }
                    return null;
                }

                using var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync(stoppingToken));
                string status = result.RootElement.GetProperty("status").GetString() ?? "";
                PollTiming timing = ReadPollTiming(result.RootElement);

                if (status == "task")
                {
                    string taskId = result.RootElement.GetProperty("task_id").GetString() ?? "";
                    string action = result.RootElement.GetProperty("action").GetString() ?? "";
                    int timeoutSeconds = result.RootElement.TryGetProperty("timeout_seconds", out var timeoutEl) && timeoutEl.TryGetInt32(out var parsedTimeout)
                        ? parsedTimeout
                        : _config.DefaultTaskTimeoutSeconds;

                    string script = "";
                    if (result.RootElement.TryGetProperty("payload", out var pl) && pl.TryGetProperty("script", out var s))
                    {
                        script = s.GetString() ?? "";
                    }

                    if (!ValidateTaskSignature(result.RootElement))
                    {
                        _logger.LogError("Task rejected by signature/journal validation; it was not executed.");
                        return timing;
                    }

                    string executionStatus = "Success";
                    string logOutput = "";

                    if (action == "reboot")
                    {
                        logOutput = "Reboot command received...";
                        await ReportResultAsync(taskId, "Success", logOutput, stoppingToken);
                        Process.Start(new ProcessStartInfo("shutdown", "/r /t 5 /c \"WinHUB Maintenance Reboot\"") { CreateNoWindow = true });
                        return timing;
                    }

                    if (action == "agent_update")
                    {
                        (executionStatus, logOutput) = await StageAndLaunchAgentUpdateAsync(taskId, result.RootElement.GetProperty("payload"), stoppingToken);
                        await ReportResultAsync(taskId, executionStatus, logOutput, stoppingToken);
                        return timing;
                    }

                    if (action is not ("run_script" or "metric" or "inventory" or "audit"))
                    {
                        await ReportResultAsync(taskId, "Error", "Unknown action is forbidden by the local agent.", stoppingToken);
                        return timing;
                    }
                    (executionStatus, logOutput) = await ExecutePowerShellAsync(script, timeoutSeconds, stoppingToken);
                    await ReportResultAsync(taskId, executionStatus, logOutput, stoppingToken);
                }
                return timing;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Polling failed: {ex.Message}");
                return null;
            }
        }

        private static async Task<string> ReadServerErrorMessageAsync(HttpResponseMessage response, CancellationToken stoppingToken)
        {
            try
            {
                string body = await response.Content.ReadAsStringAsync(stoppingToken);
                if (string.IsNullOrWhiteSpace(body)) return response.StatusCode.ToString();
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("message", out var message))
                {
                    string value = message.GetString() ?? response.StatusCode.ToString();
                    if (doc.RootElement.TryGetProperty("skew_seconds", out var skew) && skew.TryGetInt64(out long skewSeconds))
                    {
                        value += $" (skew_seconds={skewSeconds}";
                        if (doc.RootElement.TryGetProperty("server_time", out var serverTime) && serverTime.TryGetInt64(out long serverTs))
                        {
                            value += $", server_time={serverTs}";
                        }
                        if (doc.RootElement.TryGetProperty("signed_at", out var signedAt) && signedAt.TryGetInt64(out long signedTs))
                        {
                            value += $", signed_at={signedTs}";
                        }
                        value += ")";
                    }
                    return value;
                }
                if (doc.RootElement.TryGetProperty("status", out var status))
                {
                    return status.GetString() ?? response.StatusCode.ToString();
                }
            }
            catch
            {
            }
            return response.StatusCode.ToString();
        }

        private static bool IsClockSkewSignatureFailure(string serverMessage)
        {
            return serverMessage.StartsWith("signature_expired", StringComparison.OrdinalIgnoreCase)
                || serverMessage.StartsWith("invalid_signature_timestamp", StringComparison.OrdinalIgnoreCase);
        }

        private static PollTiming ReadPollTiming(JsonElement root)
        {
            return new PollTiming(
                TryGetJsonInt(root, "next_poll_after"),
                TryGetJsonInt(root, "poll_jitter_seconds"),
                TryGetJsonInt(root, "telemetry_after")
            );
        }

        private static int? TryGetJsonInt(JsonElement root, string name)
        {
            if (!root.TryGetProperty(name, out var value)) return null;
            if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int number)) return number;
            if (value.ValueKind == JsonValueKind.String && int.TryParse(value.GetString(), out number)) return number;
            return null;
        }

        private async Task<(string Status, string Log)> StageAndLaunchAgentUpdateAsync(string taskId, JsonElement payload, CancellationToken stoppingToken)
        {
            try
            {
                string packageUrl = GetPayloadString(payload, "package_url");
                string expectedSha256 = NormalizeThumbprint(GetPayloadString(payload, "sha256"));
                if (string.IsNullOrWhiteSpace(packageUrl))
                {
                    return ("Error", "agent_update requires payload.package_url.");
                }
                if (expectedSha256.Length != 64 || expectedSha256.Any(c => !Uri.IsHexDigit(c)))
                {
                    return ("Error", "agent_update requires payload.sha256 for production-safe updates.");
                }

                Uri downloadUri = BuildUpdatePackageUri(packageUrl);
                Directory.CreateDirectory(UpdatesDirectory);
                string safeTaskId = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(taskId)))[..32];
                string packagePath = Path.Combine(UpdatesDirectory, $"WinHUBAgent_{safeTaskId}.zip");
                using var downloadDeadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                downloadDeadline.CancelAfter(TimeSpan.FromMinutes(10));

                using (var response = await _httpClient.GetAsync(downloadUri, HttpCompletionOption.ResponseHeadersRead, downloadDeadline.Token))
                {
                    response.EnsureSuccessStatusCode();
                    if (response.Content.Headers.ContentLength > ProductionSecurity.MaxUpdateBytes)
                        throw new InvalidDataException("Update package exceeds 512 MiB.");
                    await using var source = await response.Content.ReadAsStreamAsync(downloadDeadline.Token);
                    await using var destination = File.Create(packagePath);
                    await ProductionSecurity.CopyBoundedAsync(source, destination, ProductionSecurity.MaxUpdateBytes, downloadDeadline.Token);
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

                string updateScript = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "update-service.ps1");
                if (!File.Exists(updateScript))
                {
                    return ("Error", $"update-service.ps1 was not found in {AppDomain.CurrentDomain.BaseDirectory}.");
                }

                string launcherPath = Path.Combine(UpdatesDirectory, $"launch_update_{safeTaskId}.ps1");
                string launcher = string.Join(Environment.NewLine, new[]
                {
                    "$ErrorActionPreference = 'Stop'",
                    "Start-Sleep -Seconds 3",
                    $"& '{EscapePowerShellSingleQuoted(updateScript)}' -PackagePath '{EscapePowerShellSingleQuoted(packagePath)}' -ExpectedSha256 '{expectedSha256}'",
                });
                await File.WriteAllTextAsync(launcherPath, launcher, new UTF8Encoding(false), stoppingToken);

                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-ExecutionPolicy Bypass -NoProfile -NonInteractive -File \"{launcherPath}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory,
                };

                Process.Start(psi);
                return ("Success", $"Agent update package staged at {packagePath}. Detached updater launched. The service will restart if the package is valid.");
            }
            catch (Exception ex)
            {
                return ("Error", $"Agent update failed before launch: {ex.Message}");
            }
        }

        private Uri BuildUpdatePackageUri(string packageUrl)
        {
            return ProductionSecurity.UpdateUri(_config.ServerUrl, packageUrl);
        }

        private static string GetPayloadString(JsonElement payload, string name)
        {
            return payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty(name, out var value)
                ? value.GetString() ?? ""
                : "";
        }

        private static string ComputeFileSha256(string path)
        {
            using var stream = File.OpenRead(path);
            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(stream)).ToUpperInvariant();
        }

        private static string EscapePowerShellSingleQuoted(string value)
        {
            return value.Replace("'", "''");
        }

        private void EnsureLocalFileSecurity()
        {
            if (!OperatingSystem.IsWindows()) return;

            try
            {
                ProductionSecurity.RejectLinks(DataDirectory);
                Directory.CreateDirectory(DataDirectory);
                HardenDirectoryAcl(DataDirectory);
                Directory.CreateDirectory(UpdatesDirectory);
                Directory.CreateDirectory(LogsDirectory);

                HardenDirectoryAcl(UpdatesDirectory);
                HardenDirectoryAcl(LogsDirectory);
                HardenDirectoryAcl(AppDomain.CurrentDomain.BaseDirectory);

                foreach (string path in new[]
                {
                    ConfigFilePath,
                    BootstrapConfigFilePath,
                    TokenFilePath,
                    SecretsFilePath,
                    HardwareIdFilePath,
                    AgentIdentityKeyFilePath,
                    TaskSigningStateFilePath
                })
                {
                    HardenFileAcl(path);
                }

                _logger.LogInformation("Local file ACL check completed.");
            }
            catch (Exception ex)
            {
                throw new IOException("Agent file permissions could not be secured. Execution is disabled.", ex);
            }
        }

        private void HardenDirectoryAcl(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path) || !OperatingSystem.IsWindows()) return;
            SecureWindowsPath(path, isDirectory: true);
        }

        private void HardenFileAcl(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path) || !OperatingSystem.IsWindows()) return;
            SecureWindowsPath(path, isDirectory: false);
        }

        internal static void SecureWindowsPath(string path, bool isDirectory)
        {
            ProductionSecurity.RejectLinks(path);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            FileSystemSecurity acl = isDirectory ? new DirectorySecurity() : new FileSecurity();
            acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            acl.SetOwner(admins);
            var inheritance = isDirectory ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None;
            foreach (var sid in new[] { system, admins })
                acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    inheritance, PropagationFlags.None, AccessControlType.Allow));
            if (isDirectory) new DirectoryInfo(path).SetAccessControl((DirectorySecurity)acl);
            else new FileInfo(path).SetAccessControl((FileSecurity)acl);
        }

        private void SaveConfig()
        {
            ProductionSecurity.AtomicWrite(ConfigFilePath,
                JsonSerializer.SerializeToUtf8Bytes(_config, AppJsonSerializerContext.Default.AgentConfig), HardenFileAcl);
        }

        private void MigratePlaintextSecretsFromConfig()
        {
            bool changed = false;
            if (!string.IsNullOrWhiteSpace(_config.GlobalApiKey))
            {
                SaveProtectedSecret("GlobalApiKey", _config.GlobalApiKey);
                _config.GlobalApiKey = "";
                changed = true;
                _logger.LogInformation("GlobalApiKey migrated to DPAPI protected storage.");
            }
            if (!string.IsNullOrWhiteSpace(_config.TaskHmacSecret))
            {
                _config.TaskHmacSecret = "";
                changed = true;
                _logger.LogInformation("Obsolete TaskHmacSecret removed from runtime config; production tasks require v2.");
            }
            if (changed)
            {
                SaveConfig();
            }
        }

        private void MigrateSecretsFromBootstrapConfig()
        {
            if (!File.Exists(BootstrapConfigFilePath)) return;
            try
            {
                string json = ProductionSecurity.ReadText(BootstrapConfigFilePath, 65536);
                var bootstrap = JsonSerializer.Deserialize(json, AppJsonSerializerContext.Default.AgentConfig);
                bool migrated = false;
                if (!string.IsNullOrWhiteSpace(bootstrap?.GlobalApiKey))
                {
                    SaveProtectedSecret("GlobalApiKey", bootstrap.GlobalApiKey);
                    migrated = true;
                    _logger.LogInformation("GlobalApiKey migrated from bootstrap config to DPAPI protected storage.");
                }
                if (!string.IsNullOrWhiteSpace(bootstrap?.TaskHmacSecret))
                {
                    migrated = true;
                    _logger.LogInformation("Obsolete bootstrap TaskHmacSecret discarded; production tasks require v2.");
                }
                if (migrated)
                {
                    File.Delete(BootstrapConfigFilePath);
                    _logger.LogInformation("Bootstrap config removed after secret migration.");
                }
            }
            catch (Exception ex)
            {
                throw new InvalidDataException("Bootstrap migration failed. Preserve the files and recover with the administrator.", ex);
            }
        }

        private async Task<(string Status, string Log)> ExecutePowerShellAsync(string scriptContent, int timeoutSeconds, CancellationToken stoppingToken)
        {
            if (string.IsNullOrEmpty(scriptContent)) return ("Error", "Empty script provided.");

            string taskDirectory = Path.Combine(DataDirectory, "tasks");
            Directory.CreateDirectory(taskDirectory);
            HardenDirectoryAcl(taskDirectory);
            string tempScriptFile = Path.Combine(taskDirectory, $"winhub_task_{Guid.NewGuid():N}.ps1");
            string outputLog = "";
            string taskStatus = "Success";
            timeoutSeconds = Math.Clamp(timeoutSeconds, 30, 86400);

            try
            {
                ProductionSecurity.AtomicWrite(tempScriptFile,
                    new UTF8Encoding(true).GetPreamble().Concat(Encoding.UTF8.GetBytes(BuildPowerShellScript(scriptContent))).ToArray(), HardenFileAcl);

                var psi = new ProcessStartInfo
                {
                    FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                    Arguments = $"-ExecutionPolicy Bypass -NoProfile -NonInteractive -File \"{tempScriptFile}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8
                };

                var capture = await ProductionSecurity.RunCapturedAsync(psi, timeoutSeconds,
                    Math.Clamp(_config.MaxResultLogBytes, 4096, 4 * 1024 * 1024), stoppingToken);
                outputLog = capture.Output;
                if (!string.IsNullOrWhiteSpace(capture.Error))
                {
                    outputLog += "\n[ERRORS]\n" + capture.Error;
                    taskStatus = "Error";
                }
                if (capture.ExitCode != 0) taskStatus = "Error";
            }
            catch (Exception ex)
            {
                taskStatus = "Error";
                outputLog = $"Exception: {ex.Message}";
            }
            finally
            {
                if (File.Exists(tempScriptFile)) File.Delete(tempScriptFile);
            }

            return (taskStatus, TrimResultLog(outputLog));
        }

        private static string BuildPowerShellScript(string scriptContent)
        {
            string encodingPreamble = @"
try {
    $script:WinHUBUtf8Encoding = [System.Text.UTF8Encoding]::new($false)
    [Console]::InputEncoding = $script:WinHUBUtf8Encoding
    [Console]::OutputEncoding = $script:WinHUBUtf8Encoding
    $OutputEncoding = $script:WinHUBUtf8Encoding
    $PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
    $PSDefaultParameterValues['Set-Content:Encoding'] = 'utf8'
    $PSDefaultParameterValues['Add-Content:Encoding'] = 'utf8'
} catch {
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $OutputEncoding = [System.Text.Encoding]::UTF8
    } catch {}
}
";
            return encodingPreamble + Environment.NewLine + scriptContent;
        }

        private async Task ReportResultAsync(string taskId, string status, string log, CancellationToken stoppingToken)
        {
            ExecutionRecord result;
            try { result = _executionJournal!.Complete(taskId, status, TrimResultLog(log)); }
            catch { _executionPersistenceFault = true; throw; }
            await SendJournalResultAsync(result, stoppingToken);
        }

        private async Task FlushJournalResultsAsync(CancellationToken stoppingToken)
        {
            if (_executionJournal == null || string.IsNullOrWhiteSpace(AuthToken)) return;
            foreach (var pending in _executionJournal.Pending())
            {
                if (stoppingToken.IsCancellationRequested) return;
                if (!await SendJournalResultAsync(pending, stoppingToken)) break;
            }
        }

        private async Task<bool> SendJournalResultAsync(ExecutionRecord pending, CancellationToken stoppingToken)
        {
            try
            {
                var unsignedPayload = new ResultPayload(HardwareId, AuthToken, AgentBuildInfo.Version, pending.TaskId, pending.Status, pending.Log, AgentPublicKeyPem, AgentKeyFingerprint, pending.KeyId, pending.Sequence, "", "", "", "");
                string unsignedJson = JsonSerializer.Serialize(unsignedPayload, AppJsonSerializerContext.Default.ResultPayload);
                string bodyHash = ComputeAgentBodyHash(unsignedJson);
                var signature = CreateAgentSignature("/api/agent/result", AuthToken, AgentBuildInfo.Version, bodyHash);
                var payload = unsignedPayload with { body_hash = bodyHash, signed_at = signature.SignedAt, signed_nonce = signature.Nonce, signature = signature.Signature };
                string jsonString = JsonSerializer.Serialize(payload, AppJsonSerializerContext.Default.ResultPayload);
                using var content = new StringContent(jsonString, Encoding.UTF8, "application/json");
                using var response = await _httpClient.PostAsync($"{_config.ServerUrl}/api/agent/result", content, stoppingToken);
                if (response.IsSuccessStatusCode && ExecutionJournal.IsSuccessAcknowledgement(await response.Content.ReadAsStringAsync(stoppingToken)))
                {
                    _executionJournal!.Acknowledge(pending.TaskId);
                    return true;
                }
                _logger.LogWarning("Task result was not acknowledged (HTTP {Status}); retained for retry. TaskId={TaskId}", response.StatusCode, pending.TaskId);
            }
            catch (Exception ex) { _logger.LogWarning("Task result retained for retry: {Message}", ex.Message); }
            return false;
        }

        private bool ValidateTaskSignature(JsonElement taskResponse)
        {
            if (!taskResponse.TryGetProperty("task_signature_v2", out var signatureV2))
            {
                _logger.LogError("Production requires a per-agent v2 signature. Legacy/unsigned tasks are refused.");
                return false;
            }
            return CanBootstrapTaskSigningKey() && ValidateTaskSignatureV2(taskResponse, signatureV2);
        }

        private bool CanBootstrapTaskSigningKey()
        {
            return Uri.TryCreate(_config.ServerUrl, UriKind.Absolute, out var uri)
                && uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                && !_config.IgnoreTlsCertificateErrors;
        }

        private bool ValidateTaskSignatureV2(JsonElement taskResponse, JsonElement envelope)
        {
            try
            {
                var verified = TaskEnvelope.Verify(taskResponse, HardwareId, _config.TaskSigningPublicKeyPem,
                    _config.TaskSigningKeyId, _config.TaskSigningLastSequence, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), CanonicalizeJson);
                _executionJournal!.Claim(taskResponse.GetProperty("task_id").GetString()!, verified.KeyId, verified.Sequence);
                _config.TaskSigningPublicKeyPem = verified.PublicKey;
                _config.TaskSigningKeyId = verified.KeyId;
                _config.TaskSigningLastSequence = verified.Sequence;
                SaveTaskSigningState();
                SaveConfig();
                RemoveProtectedSecret("TaskHmacSecret");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError("Task signature or durable-state validation failed: {Message}", ex.Message);
                return false;
            }
        }

        public static void RunProductionSelfTest() => ProductionSecurityTests.Run(CanonicalizeJson);

        private static string CanonicalizeJson(JsonElement element)
        {
            return TaskEnvelope.Canonical(element);
        }

        private static string QuoteJsonString(string? value)
        {
            return TaskEnvelope.Quote(value);
        }

        private static string ComputeHmacSha256(string secret, string message)
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        private static string ComputeAgentBodyHash(string json)
        {
            using var doc = JsonDocument.Parse(json);
            string canonical = CanonicalizeAgentRequestBody(doc.RootElement);
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        private static string CanonicalizeAgentRequestBody(JsonElement element)
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                return CanonicalizeJson(element);
            }

            string[] signatureFields = { "body_hash", "signed_at", "signed_nonce", "signature" };
            return "{" + string.Join(",", element.EnumerateObject()
                .Where(p => !signatureFields.Contains(p.Name, StringComparer.Ordinal))
                .OrderBy(p => p.Name, TaskEnvelope.PropertyComparer)
                .Select(p => QuoteJsonString(p.Name) + ":" + CanonicalizeJson(p.Value))) + "}";
        }

        private static string NormalizeThumbprint(string? value)
        {
            return new string((value ?? "").Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
        }

        private string TrimResultLog(string log)
        {
            string value = log ?? "";
            int maxBytes = Math.Clamp(_config.MaxResultLogBytes, 4096, 1024 * 1024);
            byte[] raw = Encoding.UTF8.GetBytes(value);
            if (raw.Length <= maxBytes) return value;
            string trimmed = Encoding.UTF8.GetString(raw.Take(maxBytes).ToArray());
            return trimmed + $"\n\n[WinHUB Agent] Result log truncated to {maxBytes} bytes.";
        }

        private void EnsureAgentIdentityKey()
        {
            try
            {
                Directory.CreateDirectory(DataDirectory);
                AgentIdentityKey = RSA.Create(3072);

                if (File.Exists(AgentIdentityKeyFilePath))
                {
                    byte[] protectedKey = ProductionSecurity.ReadBytes(AgentIdentityKeyFilePath, 65536);
                    byte[] privateKey = ProtectedData.Unprotect(protectedKey, null, DataProtectionScope.LocalMachine);
                    AgentIdentityKey.ImportPkcs8PrivateKey(privateKey, out _);
                }
                else
                {
                    if (File.Exists(TokenFilePath) || File.Exists(TaskSigningStateFilePath))
                        throw new InvalidDataException("Enrolled agent identity key is missing; administrator recovery is required.");
                    byte[] privateKey = AgentIdentityKey.ExportPkcs8PrivateKey();
                    byte[] protectedKey = ProtectedData.Protect(privateKey, null, DataProtectionScope.LocalMachine);
                    ProductionSecurity.AtomicWrite(AgentIdentityKeyFilePath, protectedKey, HardenFileAcl);
                    _logger.LogInformation("Generated DPAPI-protected agent identity key.");
                }

                byte[] publicKey = AgentIdentityKey.ExportSubjectPublicKeyInfo();
                if (AgentIdentityKey.KeySize < 3072) throw new InvalidDataException("Production agent identity requires RSA >= 3072 bits; explicit key rotation is required.");
                AgentPublicKeyPem = ToPem("PUBLIC KEY", publicKey);
                AgentKeyFingerprint = Convert.ToHexString(SHA256.HashData(publicKey)).ToLowerInvariant();
                _logger.LogInformation($"Agent identity key fingerprint: {AgentKeyFingerprint}");
            }
            catch (Exception ex)
            {
                AgentIdentityKey = null;
                AgentPublicKeyPem = "";
                AgentKeyFingerprint = "";
                throw new InvalidDataException("Agent identity key could not be loaded or persisted. Refusing unsigned requests.", ex);
            }
        }

        private (string SignedAt, string Nonce, string Signature) CreateAgentSignature(string path, string authToken, string agentVersion, string bodyHash)
        {
            string signedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            string nonce = Guid.NewGuid().ToString("N");
            if (AgentIdentityKey == null)
            {
                throw new CryptographicException("Agent identity key is unavailable.");
            }

            string canonical = BuildAgentSignatureMessage(path, HardwareId, authToken, agentVersion, bodyHash, signedAt, nonce);
            byte[] signature = AgentIdentityKey.SignData(
                Encoding.UTF8.GetBytes(canonical),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1
            );
            return (signedAt, nonce, Convert.ToBase64String(signature));
        }

        private static string BuildAgentSignatureMessage(string path, string hwId, string authToken, string agentVersion, string bodyHash, string signedAt, string nonce)
        {
            return string.Join("\n", new[]
            {
                path ?? "",
                hwId ?? "",
                authToken ?? "",
                agentVersion ?? "",
                bodyHash ?? "",
                signedAt ?? "",
                nonce ?? ""
            });
        }

        private static string ToPem(string label, byte[] derBytes)
        {
            string body = Convert.ToBase64String(derBytes);
            var lines = Enumerable.Range(0, (body.Length + 63) / 64)
                .Select(i => body.Substring(i * 64, Math.Min(64, body.Length - i * 64)));
            return $"-----BEGIN {label}-----\n{string.Join("\n", lines)}\n-----END {label}-----";
        }

        private AgentSecrets LoadSecretStore()
        {
            if (!File.Exists(SecretsFilePath)) return new AgentSecrets();
            try
            {
                string json = ProductionSecurity.ReadText(SecretsFilePath, 65536);
                return JsonSerializer.Deserialize(json, AppJsonSerializerContext.Default.AgentSecrets) ?? new AgentSecrets();
            }
            catch (Exception ex)
            {
                throw new InvalidDataException("Secret store is unreadable; refusing to replace it with an empty store.", ex);
            }
        }

        private void SaveSecretStore(AgentSecrets store)
        {
            Directory.CreateDirectory(DataDirectory);
            string json = JsonSerializer.Serialize(store, AppJsonSerializerContext.Default.AgentSecrets);
            ProductionSecurity.AtomicWrite(SecretsFilePath, Encoding.UTF8.GetBytes(json), HardenFileAcl);
        }

        private void SaveProtectedSecret(string name, string value)
        {
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrEmpty(value)) return;
            var store = LoadSecretStore();
            byte[] rawBytes = Encoding.UTF8.GetBytes(value);
            byte[] encryptedBytes = ProtectedData.Protect(rawBytes, null, DataProtectionScope.LocalMachine);
            string encoded = Convert.ToBase64String(encryptedBytes);
            if (name == "GlobalApiKey") store.GlobalApiKey = encoded;
            else if (name == "TaskHmacSecret") store.TaskHmacSecret = encoded;
            else return;
            SaveSecretStore(store);
        }

        private void RemoveProtectedSecret(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return;
            var store = LoadSecretStore();
            bool changed = false;
            if (name == "GlobalApiKey" && !string.IsNullOrWhiteSpace(store.GlobalApiKey))
            {
                store.GlobalApiKey = "";
                changed = true;
            }
            else if (name == "TaskHmacSecret" && !string.IsNullOrWhiteSpace(store.TaskHmacSecret))
            {
                store.TaskHmacSecret = "";
                changed = true;
            }

            if (changed)
            {
                SaveSecretStore(store);
                _logger.LogInformation($"Protected secret '{name}' removed from local store.");
            }
        }

        private string GetProtectedSecret(string name)
        {
            var store = LoadSecretStore();
            string encoded = name == "GlobalApiKey"
                ? store.GlobalApiKey
                : name == "TaskHmacSecret"
                    ? store.TaskHmacSecret
                    : "";
            if (string.IsNullOrWhiteSpace(encoded))
            {
                return "";
            }
            try
            {
                byte[] encryptedBytes = Convert.FromBase64String(encoded);
                byte[] rawBytes = ProtectedData.Unprotect(encryptedBytes, null, DataProtectionScope.LocalMachine);
                return Encoding.UTF8.GetString(rawBytes);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to decrypt protected secret '{name}': {ex.Message}");
                return "";
            }
        }

        private string GetHardwareId()
        {
            string machineGuid = GetMachineGuid();
            string[] macs = GetStableMacAddresses();
            string source = string.Join("|", new[]
            {
                "winhub-agent-v2",
                machineGuid,
                Environment.MachineName,
                string.Join(",", macs)
            });

            if (string.IsNullOrWhiteSpace(machineGuid) && macs.Length == 0)
            {
                return "HWID-FALLBACK-" + Environment.MachineName;
            }

            using var sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(source));
            return "WINHUB-" + Convert.ToHexString(hash).ToLowerInvariant();
        }

        private string GetOrCreateHardwareId()
        {
            return ProductionSecurity.HardwareIdentity(HardwareIdFilePath,
                File.Exists(TokenFilePath) || File.Exists(AgentIdentityKeyFilePath) || File.Exists(TaskSigningStateFilePath),
                GeneratePersistentHardwareId, HardenFileAcl);
        }

        private static string GeneratePersistentHardwareId()
        {
            using var sha = SHA256.Create();
            string source = string.Join("|", new[]
            {
                "winhub-agent-install-v1",
                Guid.NewGuid().ToString("N"),
                GetMachineGuid(),
                Environment.MachineName,
                DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString()
            });
            byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(source));
            return "WINHUB-" + Convert.ToHexString(hash).ToLowerInvariant();
        }

        private static string GetMachineGuid()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
                if (key != null)
                {
                    var guid = key.GetValue("MachineGuid")?.ToString();
                    if (!string.IsNullOrWhiteSpace(guid)) return guid.Trim();
                }
            }
            catch { }
            return "";
        }

        private static string[] GetStableMacAddresses()
        {
            try
            {
                return NetworkInterface.GetAllNetworkInterfaces()
                    .Where(nic =>
                        nic.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        nic.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                    .Select(nic => nic.GetPhysicalAddress().ToString().Trim().ToUpperInvariant())
                    .Where(mac => !string.IsNullOrWhiteSpace(mac))
                    .Distinct()
                    .OrderBy(mac => mac, StringComparer.Ordinal)
                    .ToArray();
            }
            catch
            {
                return Array.Empty<string>();
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
                        string[] ipv4 = props.UnicastAddresses
                            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                            .Select(a => a.Address.ToString())
                            .ToArray();
                        string[] ipv6 = props.UnicastAddresses
                            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetworkV6)
                            .Select(a => a.Address.ToString())
                            .ToArray();
                        string[] gateways = props.GatewayAddresses
                            .Select(g => g.Address.ToString())
                            .Where(v => !string.IsNullOrWhiteSpace(v))
                            .ToArray();
                        string[] dns = props.DnsAddresses
                            .Select(d => d.ToString())
                            .ToArray();
                        bool dhcp = false;
                        try
                        {
                            dhcp = props.GetIPv4Properties()?.IsDhcpEnabled ?? false;
                        }
                        catch { }

                        return new NetworkInterfaceInfo(
                            nic.Name,
                            nic.Description,
                            nic.NetworkInterfaceType.ToString(),
                            nic.OperationalStatus.ToString(),
                            nic.GetPhysicalAddress().ToString(),
                            ipv4,
                            ipv6,
                            gateways,
                            dns,
                            dhcp,
                            Math.Max(0, nic.Speed / 1000000)
                        );
                    })
                    .ToArray();
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Failed to collect network interfaces: {ex.Message}");
                return Array.Empty<NetworkInterfaceInfo>();
            }
        }

        private static bool RegistryKeyExists(string path)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                return key != null;
            }
            catch { return false; }
        }

        private static bool RegistryValueExists(string path, string valueName)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path);
                return key?.GetValue(valueName) != null;
            }
            catch { return false; }
        }

        private static string FirewallProfileState(string profileName)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profileName}");
                var value = key?.GetValue("EnableFirewall");
                if (value == null) return "unknown";
                return Convert.ToInt32(value) == 1 ? "enabled" : "disabled";
            }
            catch { return "unknown"; }
        }

        private static string RunCommandSnapshot(string fileName, string arguments, int timeoutSeconds, int maxChars)
        {
            try
            {
                Encoding outputEncoding = Encoding.UTF8;
                try
                {
                    outputEncoding = Encoding.GetEncoding((int)GetOEMCP());
                }
                catch { }

                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = outputEncoding,
                    StandardErrorEncoding = outputEncoding
                };

                using var process = Process.Start(psi);
                if (process == null) return "unavailable";
                var stdoutTask = process.StandardOutput.ReadToEndAsync();
                var stderrTask = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(timeoutSeconds * 1000))
                {
                    try { process.Kill(true); } catch { }
                    return "timeout";
                }
                string output = (stdoutTask.GetAwaiter().GetResult() + "\n" + stderrTask.GetAwaiter().GetResult()).Trim();
                if (string.IsNullOrWhiteSpace(output)) return process.ExitCode == 0 ? "ok" : $"exit {process.ExitCode}";
                return output.Length > maxChars ? output.Substring(0, maxChars) + "\n[truncated]" : output;
            }
            catch { return "unavailable"; }
        }

        private static BitLockerInventoryInfo GetBitLockerInventory()
        {
            string raw = RunCommandSnapshot("manage-bde.exe", "-status C:", 8, 3000);
            string lower = raw.ToLowerInvariant();
            int encryptedPercentage = -1;

            try
            {
                var percentMatch = System.Text.RegularExpressions.Regex.Match(
                    raw,
                    @"(?i)(percentage encrypted|encrypted percentage|зашифровано|зашифрован[а-я\s]*\(%\)|процент[а-я\s]*шифр)[^\d]*(\d+)",
                    System.Text.RegularExpressions.RegexOptions.CultureInvariant
                );
                if (percentMatch.Success)
                    int.TryParse(percentMatch.Groups[2].Value, out encryptedPercentage);
            }
            catch { }

            string protection = "unknown";
            if (lower.Contains("protection on") || lower.Contains("защита включена") || lower.Contains("захист увімк"))
                protection = "on";
            else if (lower.Contains("protection off") || lower.Contains("защита отключена") || lower.Contains("захист вимк"))
                protection = "off";

            string conversion = "unknown";
            if (lower.Contains("fully encrypted") || lower.Contains("полностью зашифрован") || lower.Contains("повністю зашифр"))
                conversion = "fully_encrypted";
            else if (lower.Contains("fully decrypted") || lower.Contains("полностью расшифрован") || lower.Contains("повністю розшифр"))
                conversion = "fully_decrypted";
            else if (lower.Contains("encryption in progress") || lower.Contains("шифрование выполняется") || lower.Contains("шифрування виконується"))
                conversion = "encryption_in_progress";

            string status = "unknown";
            if (encryptedPercentage == 100 || protection == "on" || conversion == "fully_encrypted")
                status = "encrypted";
            else if (encryptedPercentage > 0 || conversion == "encryption_in_progress")
                status = "partial";
            else if (encryptedPercentage == 0 || protection == "off" || conversion == "fully_decrypted")
                status = "not_encrypted";

            return new BitLockerInventoryInfo(status, encryptedPercentage, protection, conversion, raw);
        }

        private static bool ServiceOrDriverExists(string serviceName)
        {
            string output = RunCommandSnapshot("sc.exe", $"query {serviceName}", 5, 1200);
            return output.IndexOf("SERVICE_NAME", StringComparison.OrdinalIgnoreCase) >= 0
                || output.IndexOf("RUNNING", StringComparison.OrdinalIgnoreCase) >= 0
                || output.IndexOf("STOPPED", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool InstalledSoftwareContains(string productName)
        {
            string[] roots =
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            };
            foreach (string root in roots)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(root);
                    if (key == null) continue;
                    foreach (string subName in key.GetSubKeyNames())
                    {
                        using var sub = key.OpenSubKey(subName);
                        string display = Convert.ToString(sub?.GetValue("DisplayName")) ?? "";
                        if (display.IndexOf(productName, StringComparison.OrdinalIgnoreCase) >= 0)
                            return true;
                    }
                }
                catch { }
            }
            return false;
        }

        private SecurityInventoryInfo GetSecurityInventory()
        {
            bool pendingReboot =
                RegistryKeyExists(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") ||
                RegistryKeyExists(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") ||
                RegistryValueExists(@"SYSTEM\CurrentControlSet\Control\Session Manager", "PendingFileRenameOperations");

            string defenderState = RunCommandSnapshot("sc.exe", "query WinDefend", 5, 1200);
            if (defenderState.IndexOf("RUNNING", StringComparison.OrdinalIgnoreCase) >= 0)
                defenderState = "running";
            else if (defenderState.IndexOf("STOPPED", StringComparison.OrdinalIgnoreCase) >= 0)
                defenderState = "stopped";
            else if (defenderState.IndexOf("does not exist", StringComparison.OrdinalIgnoreCase) >= 0)
                defenderState = "not_installed";

            BitLockerInventoryInfo bitlocker = GetBitLockerInventory();

            return new SecurityInventoryInfo(
                pendingReboot,
                FirewallProfileState("DomainProfile"),
                FirewallProfileState("StandardProfile"),
                FirewallProfileState("PublicProfile"),
                bitlocker.raw_summary,
                bitlocker,
                defenderState,
                RegistryKeyExists(@"SOFTWARE\IDRIX\VeraCrypt") || InstalledSoftwareContains("VeraCrypt") || ServiceOrDriverExists("veracrypt"),
                RegistryKeyExists(@"SOFTWARE\TrueCrypt") || InstalledSoftwareContains("TrueCrypt") || ServiceOrDriverExists("truecrypt")
            );
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
            string fqdn = Environment.MachineName;
            string domainName = "";
            try
            {
                var ipProps = IPGlobalProperties.GetIPGlobalProperties();
                domainName = ipProps.DomainName ?? "";
                if (!string.IsNullOrWhiteSpace(domainName))
                {
                    fqdn = $"{Environment.MachineName}.{domainName}";
                }
            }
            catch { }

            ulong totalMemoryMb = 0;
            try
            {
                MEMORYSTATUSEX memStatus = new MEMORYSTATUSEX();
                memStatus.dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>();
                if (GlobalMemoryStatusEx(ref memStatus))
                {
                    totalMemoryMb = memStatus.ullTotalPhys / 1024 / 1024;
                }
            }
            catch { }

            long uptimeSeconds = 0;
            string bootTimeUtc = "";
            try
            {
                uptimeSeconds = Environment.TickCount64 / 1000;
                bootTimeUtc = DateTime.UtcNow.AddSeconds(-uptimeSeconds).ToString("o");
            }
            catch { }

            VolumeInfo[] volumes = Array.Empty<VolumeInfo>();
            try
            {
                volumes = DriveInfo.GetDrives().Select(d =>
                {
                    bool ready = d.IsReady;
                    return new VolumeInfo(
                        d.Name,
                        ready ? d.VolumeLabel : "",
                        ready ? d.DriveFormat : "",
                        d.DriveType.ToString(),
                        ready ? (long)Math.Round(d.TotalSize / 1024.0 / 1024.0 / 1024.0) : 0,
                        ready ? (long)Math.Round(d.AvailableFreeSpace / 1024.0 / 1024.0 / 1024.0) : 0,
                        ready
                    );
                }).ToArray();
            }
            catch { }

            string userDomain = "";
            try { userDomain = Environment.UserDomainName; } catch { }

            return new HostInventoryInfo(
                Environment.MachineName,
                fqdn,
                domainName,
                userDomain,
                !string.IsNullOrWhiteSpace(domainName) || (!string.IsNullOrWhiteSpace(userDomain) && !string.Equals(userDomain, Environment.MachineName, StringComparison.OrdinalIgnoreCase)),
                RuntimeInformation.OSDescription,
                RuntimeInformation.OSArchitecture.ToString(),
                RuntimeInformation.ProcessArchitecture.ToString(),
                TimeZoneInfo.Local.Id,
                Environment.ProcessorCount,
                totalMemoryMb,
                uptimeSeconds,
                bootTimeUtc,
                volumes,
                GetSecurityInventory()
            );
        }

        private void SaveToken(string token)
        {
            if (string.IsNullOrWhiteSpace(token)) throw new InvalidDataException("Server returned an empty enrollment token.");
            if (string.IsNullOrEmpty(token)) return;
            byte[] rawBytes = Encoding.UTF8.GetBytes(token);
            byte[] encryptedBytes = ProtectedData.Protect(rawBytes, null, DataProtectionScope.LocalMachine);
            ProductionSecurity.AtomicWrite(TokenFilePath, encryptedBytes, HardenFileAcl);
        }

        private bool LoadToken()
        {
            if (!File.Exists(TokenFilePath)) return false;
            try
            {
                byte[] encryptedBytes = ProductionSecurity.ReadBytes(TokenFilePath, 65536);
                byte[] rawBytes = ProtectedData.Unprotect(encryptedBytes, null, DataProtectionScope.LocalMachine);
                AuthToken = Encoding.UTF8.GetString(rawBytes);
                if (string.IsNullOrWhiteSpace(AuthToken)) throw new InvalidDataException("Saved enrollment token is empty.");
                return true;
            }
            catch (Exception ex) { throw new InvalidDataException("Saved enrollment token is unreadable; administrator recovery is required.", ex); }
        }
    }
}
