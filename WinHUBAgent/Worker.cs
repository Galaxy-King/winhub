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

namespace WinHUBAgent
{
    // --- МОДЕЛІ ДАНИХ ---
    public record EnrollPayload(string global_token, string hw_id, string hostname, string os_version, string os_type, string agent_version, NetworkInterfaceInfo[] network_interfaces, HostInventoryInfo host_info, string previous_auth_token, string previous_hw_id, string agent_public_key_pem, string agent_key_fingerprint, string signed_at, string signed_nonce, string signature);
    public record PollPayload(string hw_id, string auth_token, string agent_version, string agent_public_key_pem, string agent_key_fingerprint, string signed_at, string signed_nonce, string signature);
    public record TelemetryPayload(string hw_id, string auth_token, string agent_version, double cpu, double ram, double disk_c, HostInventoryInfo? host_info, string agent_public_key_pem, string agent_key_fingerprint, string signed_at, string signed_nonce, string signature);
    public record ResultPayload(string hw_id, string auth_token, string agent_version, string task_id, string status, string log, string agent_public_key_pem, string agent_key_fingerprint, string signed_at, string signed_nonce, string signature);
    public record NetworkInterfaceInfo(string name, string description, string type, string status, string mac, string[] ipv4, string[] ipv6, string[] gateways, string[] dns_servers, bool dhcp_enabled, long speed_mbps);
    public record VolumeInfo(string name, string label, string format, string type, long total_gb, long free_gb, bool ready);
    public record BitLockerInventoryInfo(string status, int encrypted_percentage, string protection_status, string conversion_status, string raw_summary);
    public record SecurityInventoryInfo(bool pending_reboot, string firewall_domain, string firewall_private, string firewall_public, string bitlocker_summary, BitLockerInventoryInfo bitlocker, string defender_service_state, bool veracrypt_detected, bool truecrypt_detected);
    public record HostInventoryInfo(string machine_name, string fqdn, string domain_name, string user_domain_name, bool likely_domain_joined, string os_description, string os_architecture, string process_architecture, string timezone, int processor_count, ulong total_memory_mb, long uptime_seconds, string boot_time_utc, VolumeInfo[] volumes, SecurityInventoryInfo security);

    // НОВЕ: Модель для конфігурації
    public class AgentConfig
    {
        public string ServerUrl { get; set; } = "https://192.168.37.223:8443";
        public string GlobalApiKey { get; set; } = "";
        public int PollIntervalSeconds { get; set; } = 30;
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
    [JsonSerializable(typeof(AgentConfig))] // Додано для конфігу
    [JsonSerializable(typeof(AgentSecrets))]
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
        private readonly Random _random = new Random();
        private bool _signatureWarningLogged = false;

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
            
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
                {
                    if (_config.IgnoreTlsCertificateErrors) return true;
                    string pinned = NormalizeThumbprint(_config.ServerCertificateSha256);
                    if (!string.IsNullOrWhiteSpace(pinned) && cert != null)
                    {
                        string actual = NormalizeThumbprint(cert.GetCertHashString(HashAlgorithmName.SHA256));
                        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(actual), Encoding.ASCII.GetBytes(pinned));
                    }
                    return errors == System.Net.Security.SslPolicyErrors.None;
                }
            };
            _httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        }

        // НОВЕ: Метод для завантаження конфігурації
        private void LoadConfig()
        {
            if (File.Exists(ConfigFilePath))
            {
                try
                {
                    string json = File.ReadAllText(ConfigFilePath);
                    var loadedConfig = JsonSerializer.Deserialize(json, AppJsonSerializerContext.Default.AgentConfig);
                    if (loadedConfig != null) _config = loadedConfig;
                    _config.ServerUrl = (_config.ServerUrl ?? "").Trim().TrimEnd('/');
                    _httpClient.Timeout = TimeSpan.FromSeconds(Math.Max(10, Math.Min(300, _config.DefaultTaskTimeoutSeconds)));
                    _logger.LogInformation($"Runtime config loaded. Server: {_config.ServerUrl}");
                    MigratePlaintextSecretsFromConfig();
                    MigrateSecretsFromBootstrapConfig();
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Failed to read config file. Using default settings. Error: {ex.Message}");
                }
            }
            else
            {
                // Створюємо файл зі стандартними налаштуваннями, якщо його немає
                try
                {
                    string json = JsonSerializer.Serialize(_config, AppJsonSerializerContext.Default.AgentConfig);
                    File.WriteAllText(ConfigFilePath, json);
                    _logger.LogInformation($"Created default config at {ConfigFilePath}");
                    MigrateSecretsFromBootstrapConfig();
                }
                catch (Exception ex)
                {
                    _logger.LogWarning($"Could not create default config file: {ex.Message}");
                }
            }
        }

        // НОВЕ: Отримання людської назви ОС з Реєстру
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
            _logger.LogInformation("WinHUB Agent Service starting...");
            
            // Завантажуємо налаштування з файлу
            LoadConfig();
            
            Directory.CreateDirectory(DataDirectory);

            HardwareId = GetOrCreateHardwareId();
            EnsureAgentIdentityKey();
            FriendlyOsName = GetFriendlyOsName();
            
            _logger.LogInformation($"Hardware ID: {HardwareId}");
            _logger.LogInformation($"OS Detected: {FriendlyOsName}");
            
            if (!LoadToken())
            {
                _logger.LogWarning("Initiating Enrollment...");
                await EnrollAgentAsync(stoppingToken);
            }

            DateTime lastTelemetrySent = DateTime.MinValue;

            while (!stoppingToken.IsCancellationRequested)
            {
                if ((DateTime.UtcNow - lastTelemetrySent).TotalMinutes >= 5)
                {
                    await SendTelemetryAsync(stoppingToken);
                    lastTelemetrySent = DateTime.UtcNow;
                }

                await PollServerAsync(stoppingToken);

                // Використовуємо інтервал з конфігурації + джитер (розкид)
                int jitter = _random.Next(-5, 16); 
                int nextPoll = Math.Max(10, _config.PollIntervalSeconds + jitter);
                await Task.Delay(TimeSpan.FromSeconds(nextPoll), stoppingToken);
            }
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

                var signature = CreateAgentSignature("/api/agent/telemetry", AuthToken, AgentBuildInfo.Version);
                var payload = new TelemetryPayload(HardwareId, AuthToken, AgentBuildInfo.Version, Math.Round(cpuUsage, 2), ramUsage, diskCFree, GetCachedHostInventory(false), AgentPublicKeyPem, AgentKeyFingerprint, signature.SignedAt, signature.Nonce, signature.Signature);
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
                    var signature = CreateAgentSignature("/api/agent/enroll", previousAuthToken, AgentBuildInfo.Version);
                    var payload = new EnrollPayload(enrollmentToken, HardwareId, Environment.MachineName, FriendlyOsName, "Windows", AgentBuildInfo.Version, GetNetworkInterfaces(), GetCachedHostInventory(true), previousAuthToken, previousHwId, AgentPublicKeyPem, AgentKeyFingerprint, signature.SignedAt, signature.Nonce, signature.Signature);
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

        private async Task PollServerAsync(CancellationToken stoppingToken)
        {
            try
            {
                var signature = CreateAgentSignature("/api/agent/poll", AuthToken, AgentBuildInfo.Version);
                var payload = new PollPayload(HardwareId, AuthToken, AgentBuildInfo.Version, AgentPublicKeyPem, AgentKeyFingerprint, signature.SignedAt, signature.Nonce, signature.Signature);
                string jsonString = JsonSerializer.Serialize(payload, AppJsonSerializerContext.Default.PollPayload);
                var content = new StringContent(jsonString, Encoding.UTF8, "application/json");
                
                var response = await _httpClient.PostAsync($"{_config.ServerUrl}/api/agent/poll", content, stoppingToken);
                if (!response.IsSuccessStatusCode)
                {
                    if (response.StatusCode == System.Net.HttpStatusCode.Forbidden || response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        string previousAuthToken = AuthToken;
                        string previousHwId = HardwareId;
                        _logger.LogWarning("Server rejected poll token. Attempting secure re-enrollment with previous token proof.");
                        await EnrollAgentAsync(stoppingToken, previousAuthToken, previousHwId);
                    }
                    return;
                }

                var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                string status = result.RootElement.GetProperty("status").GetString() ?? "";

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
                        await ReportResultAsync(taskId, "Error", "Task signature verification failed. Task was not executed.", stoppingToken);
                        return;
                    }

                    string executionStatus = "Success";
                    string logOutput = "";

                    if (action == "reboot")
                    {
                        logOutput = "Reboot command received...";
                        await ReportResultAsync(taskId, "Success", logOutput, stoppingToken);
                        Process.Start(new ProcessStartInfo("shutdown", "/r /t 5 /c \"WinHUB Maintenance Reboot\"") { CreateNoWindow = true });
                        return;
                    }

                    if (action == "agent_update")
                    {
                        (executionStatus, logOutput) = await StageAndLaunchAgentUpdateAsync(taskId, result.RootElement.GetProperty("payload"), stoppingToken);
                        await ReportResultAsync(taskId, executionStatus, logOutput, stoppingToken);
                        return;
                    }
	
                    (executionStatus, logOutput) = await ExecutePowerShellAsync(script, timeoutSeconds, stoppingToken);
                    await ReportResultAsync(taskId, executionStatus, logOutput, stoppingToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Polling failed: {ex.Message}");
            }
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

                Uri downloadUri = BuildUpdatePackageUri(packageUrl);
                Directory.CreateDirectory(UpdatesDirectory);
                string packagePath = Path.Combine(UpdatesDirectory, $"WinHUBAgent_{taskId}.zip");

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

                string updateScript = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "update-service.ps1");
                if (!File.Exists(updateScript))
                {
                    return ("Error", $"update-service.ps1 was not found in {AppDomain.CurrentDomain.BaseDirectory}.");
                }

                string launcherPath = Path.Combine(UpdatesDirectory, $"launch_update_{taskId}.ps1");
                string launcher = string.Join(Environment.NewLine, new[]
                {
                    "$ErrorActionPreference = 'Stop'",
                    "Start-Sleep -Seconds 3",
                    $"& '{EscapePowerShellSingleQuoted(updateScript)}' -PackagePath '{EscapePowerShellSingleQuoted(packagePath)}'",
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
            if (Uri.TryCreate(packageUrl, UriKind.Absolute, out var absolute))
            {
                return absolute;
            }
            return new Uri(new Uri(_config.ServerUrl.TrimEnd('/') + "/"), packageUrl.TrimStart('/'));
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

        private void SaveConfig()
        {
            try
            {
                string json = JsonSerializer.Serialize(_config, AppJsonSerializerContext.Default.AgentConfig);
                File.WriteAllText(ConfigFilePath, json);
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Could not update config file to remove plaintext secrets: {ex.Message}");
            }
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
                SaveProtectedSecret("TaskHmacSecret", _config.TaskHmacSecret);
                _config.TaskHmacSecret = "";
                changed = true;
                _logger.LogInformation("TaskHmacSecret migrated to DPAPI protected storage.");
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
                string json = File.ReadAllText(BootstrapConfigFilePath);
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
                    SaveProtectedSecret("TaskHmacSecret", bootstrap.TaskHmacSecret);
                    migrated = true;
                    _logger.LogInformation("TaskHmacSecret migrated from bootstrap config to DPAPI protected storage.");
                }
                if (migrated)
                {
                    try
                    {
                        File.Delete(BootstrapConfigFilePath);
                        _logger.LogInformation("Bootstrap config removed after secret migration.");
                    }
                    catch (Exception deleteEx)
                    {
                        _logger.LogWarning($"Could not delete bootstrap config after migration: {deleteEx.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to read bootstrap config: {ex.Message}");
            }
        }

        private async Task<(string Status, string Log)> ExecutePowerShellAsync(string scriptContent, int timeoutSeconds, CancellationToken stoppingToken)
        {
            if (string.IsNullOrEmpty(scriptContent)) return ("Error", "Empty script provided.");

            string tempScriptFile = Path.Combine(Path.GetTempPath(), $"winhub_task_{Guid.NewGuid()}.ps1");
            string outputLog = "";
            string taskStatus = "Success";
            timeoutSeconds = Math.Clamp(timeoutSeconds, 30, 86400);

            try
            {
                await File.WriteAllTextAsync(tempScriptFile, BuildPowerShellScript(scriptContent), new UTF8Encoding(true), stoppingToken);

                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-ExecutionPolicy Bypass -NoProfile -NonInteractive -File \"{tempScriptFile}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    StandardOutputEncoding = Encoding.UTF8,
                    StandardErrorEncoding = Encoding.UTF8
                };

                using var process = Process.Start(psi);
                if (process == null) throw new Exception("Process start failed.");

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeoutCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

                var stdOutTask = process.StandardOutput.ReadToEndAsync(timeoutCts.Token);
                var stdErrTask = process.StandardError.ReadToEndAsync(timeoutCts.Token);

                try
                {
                    await process.WaitForExitAsync(timeoutCts.Token);
                }
                catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
                {
                    try
                    {
                        process.Kill(entireProcessTree: true);
                    }
                    catch { }
                    return ("Error", $"Task timeout after {timeoutSeconds} seconds. Process was terminated.");
                }

                outputLog = await stdOutTask;
                string stdErr = await stdErrTask;

                if (!string.IsNullOrWhiteSpace(stdErr))
                {
                    outputLog += "\n[ERRORS]\n" + stdErr;
                    taskStatus = "Error"; 
                }
                if (process.ExitCode != 0) taskStatus = "Error";
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
            try
            {
                var signature = CreateAgentSignature("/api/agent/result", AuthToken, AgentBuildInfo.Version);
                var payload = new ResultPayload(HardwareId, AuthToken, AgentBuildInfo.Version, taskId, status, TrimResultLog(log), AgentPublicKeyPem, AgentKeyFingerprint, signature.SignedAt, signature.Nonce, signature.Signature);
                string jsonString = JsonSerializer.Serialize(payload, AppJsonSerializerContext.Default.ResultPayload);
                var content = new StringContent(jsonString, Encoding.UTF8, "application/json");
                await _httpClient.PostAsync($"{_config.ServerUrl}/api/agent/result", content, stoppingToken);
            }
            catch { }
        }

        private bool ValidateTaskSignature(JsonElement taskResponse)
        {
            string secret = GetProtectedSecret("TaskHmacSecret");
            bool hasSignature = taskResponse.TryGetProperty("signature", out var signatureEl);
            string providedSignature = hasSignature ? (signatureEl.GetString() ?? "") : "";

            if (string.IsNullOrWhiteSpace(secret))
            {
                if (_config.RequireTaskSignature)
                {
                    _logger.LogError("TaskHmacSecret is empty and RequireTaskSignature=true. Refusing task execution.");
                    return false;
                }
                if (!_signatureWarningLogged)
                {
                    _logger.LogWarning("TaskHmacSecret is empty. Task signature verification is disabled for backward compatibility.");
                    _signatureWarningLogged = true;
                }
                return true;
            }

            if (string.IsNullOrWhiteSpace(providedSignature))
            {
                _logger.LogError("Server returned a task without signature. Refusing execution.");
                return false;
            }

            string taskId = taskResponse.GetProperty("task_id").GetString() ?? "";
            string action = taskResponse.GetProperty("action").GetString() ?? "";
            JsonElement payload = taskResponse.GetProperty("payload");
            string canonical = "{\"action\":" + QuoteJsonString(action) +
                               ",\"payload\":" + CanonicalizeJson(payload) +
                               ",\"task_id\":" + QuoteJsonString(taskId) + "}";
            string expected = ComputeHmacSha256(secret, canonical);
            string normalizedSignature = providedSignature.ToLowerInvariant();
            bool valid = expected.Length == normalizedSignature.Length &&
                CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(expected),
                    Encoding.ASCII.GetBytes(normalizedSignature)
                );
            if (!valid)
            {
                _logger.LogError($"Invalid task signature for task {taskId}. Refusing execution.");
            }
            return valid;
        }

        private static string CanonicalizeJson(JsonElement element)
        {
            return element.ValueKind switch
            {
                JsonValueKind.Object => "{" + string.Join(",", element.EnumerateObject()
                    .OrderBy(p => p.Name, StringComparer.Ordinal)
                    .Select(p => QuoteJsonString(p.Name) + ":" + CanonicalizeJson(p.Value))) + "}",
                JsonValueKind.Array => "[" + string.Join(",", element.EnumerateArray().Select(CanonicalizeJson)) + "]",
                JsonValueKind.String => QuoteJsonString(element.GetString()),
                JsonValueKind.Number => element.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Null => "null",
                _ => element.GetRawText()
            };
        }

        private static string QuoteJsonString(string? value)
        {
            return "\"" + JsonEncodedText.Encode(value ?? "", JavaScriptEncoder.UnsafeRelaxedJsonEscaping).ToString() + "\"";
        }

        private static string ComputeHmacSha256(string secret, string message)
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(message));
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        private static string NormalizeThumbprint(string? value)
        {
            return new string((value ?? "").Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
        }

        private string TrimResultLog(string log)
        {
            string value = log ?? "";
            int maxBytes = Math.Max(4096, _config.MaxResultLogBytes);
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
                    byte[] protectedKey = File.ReadAllBytes(AgentIdentityKeyFilePath);
                    byte[] privateKey = ProtectedData.Unprotect(protectedKey, null, DataProtectionScope.LocalMachine);
                    AgentIdentityKey.ImportPkcs8PrivateKey(privateKey, out _);
                }
                else
                {
                    byte[] privateKey = AgentIdentityKey.ExportPkcs8PrivateKey();
                    byte[] protectedKey = ProtectedData.Protect(privateKey, null, DataProtectionScope.LocalMachine);
                    File.WriteAllBytes(AgentIdentityKeyFilePath, protectedKey);
                    _logger.LogInformation("Generated DPAPI-protected agent identity key.");
                }

                byte[] publicKey = AgentIdentityKey.ExportSubjectPublicKeyInfo();
                AgentPublicKeyPem = ToPem("PUBLIC KEY", publicKey);
                AgentKeyFingerprint = Convert.ToHexString(SHA256.HashData(publicKey)).ToLowerInvariant();
                _logger.LogInformation($"Agent identity key fingerprint: {AgentKeyFingerprint}");
            }
            catch (Exception ex)
            {
                AgentIdentityKey = null;
                AgentPublicKeyPem = "";
                AgentKeyFingerprint = "";
                _logger.LogError($"Failed to load or create agent identity key: {ex.Message}");
            }
        }

        private (string SignedAt, string Nonce, string Signature) CreateAgentSignature(string path, string authToken, string agentVersion)
        {
            string signedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
            string nonce = Guid.NewGuid().ToString("N");
            if (AgentIdentityKey == null)
            {
                return (signedAt, nonce, "");
            }

            string canonical = BuildAgentSignatureMessage(path, HardwareId, authToken, agentVersion, signedAt, nonce);
            byte[] signature = AgentIdentityKey.SignData(
                Encoding.UTF8.GetBytes(canonical),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1
            );
            return (signedAt, nonce, Convert.ToBase64String(signature));
        }

        private static string BuildAgentSignatureMessage(string path, string hwId, string authToken, string agentVersion, string signedAt, string nonce)
        {
            return string.Join("\n", new[]
            {
                path ?? "",
                hwId ?? "",
                authToken ?? "",
                agentVersion ?? "",
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
                string json = File.ReadAllText(SecretsFilePath);
                return JsonSerializer.Deserialize(json, AppJsonSerializerContext.Default.AgentSecrets) ?? new AgentSecrets();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to read protected secret store: {ex.Message}");
                return new AgentSecrets();
            }
        }

        private void SaveSecretStore(AgentSecrets store)
        {
            Directory.CreateDirectory(DataDirectory);
            string json = JsonSerializer.Serialize(store, AppJsonSerializerContext.Default.AgentSecrets);
            File.WriteAllText(SecretsFilePath, json);
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
            try
            {
                if (File.Exists(HardwareIdFilePath))
                {
                    string saved = File.ReadAllText(HardwareIdFilePath).Trim();
                    if (saved.StartsWith("WINHUB-", StringComparison.OrdinalIgnoreCase) || saved.StartsWith("HWID-FALLBACK-", StringComparison.OrdinalIgnoreCase))
                    {
                        return saved;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Failed to read persisted hardware ID: {ex.Message}");
            }

            string generated = GeneratePersistentHardwareId();
            try
            {
                Directory.CreateDirectory(DataDirectory);
                File.WriteAllText(HardwareIdFilePath, generated, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                _logger.LogWarning($"Failed to persist hardware ID: {ex.Message}");
            }
            return generated;
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
            if (string.IsNullOrEmpty(token)) return;
            byte[] rawBytes = Encoding.UTF8.GetBytes(token);
            byte[] encryptedBytes = ProtectedData.Protect(rawBytes, null, DataProtectionScope.LocalMachine);
            File.WriteAllBytes(TokenFilePath, encryptedBytes);
        }

        private bool LoadToken()
        {
            if (!File.Exists(TokenFilePath)) return false;
            try
            {
                byte[] encryptedBytes = File.ReadAllBytes(TokenFilePath);
                byte[] rawBytes = ProtectedData.Unprotect(encryptedBytes, null, DataProtectionScope.LocalMachine);
                AuthToken = Encoding.UTF8.GetString(rawBytes);
                return !string.IsNullOrWhiteSpace(AuthToken);
            }
            catch { return false; }
        }
    }
}
