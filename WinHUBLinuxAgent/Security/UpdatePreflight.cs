using System.Net.Http;
using System.Security.Authentication;
using System.Text.Json;

namespace WinHUB.Security;

internal static class UpdatePreflight
{
    // Read-only: no enrollment, poll, token, sequence or service startup.
    internal static async Task CheckServerAsync(string configPath)
    {
        LinuxTaskProcess.CheckPrerequisites();
        using var config = JsonDocument.Parse(ProductionSecurity.ReadText(configPath));
        var root = config.RootElement;
        string Text(string key) => root.TryGetProperty(key, out var value) ? value.GetString() ?? "" : "";
        bool Flag(string key, bool fallback) => root.TryGetProperty(key, out var value) ? value.GetBoolean() : fallback;
        string pin = Text("ServerCertificateSha256"), nextPin = Text("ServerCertificateSha256Next");
        Uri origin = ProductionSecurity.ValidateConfiguration(Text("ServerUrl"), pin, nextPin,
            Flag("IgnoreTlsCertificateErrors", false), Flag("RequireTaskSignature", true));
        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            ServerCertificateCustomValidationCallback = (_, certificate, _, _) =>
                ProductionSecurity.CertificateMatches(certificate, pin, nextPin)
        };
        using var client = new HttpClient(handler);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var response = await client.GetAsync(new Uri(origin, "/api/health"), HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        response.EnsureSuccessStatusCode();
        using var source = await response.Content.ReadAsStreamAsync(deadline.Token);
        using var output = new MemoryStream();
        await ProductionSecurity.CopyBoundedAsync(source, output, 65536, deadline.Token);
        using var health = JsonDocument.Parse(output.ToArray());
        if (!health.RootElement.TryGetProperty("status", out var status) || status.GetString() != "ok")
            throw new InvalidDataException("WinHUB health check did not return status=ok.");
    }
}
