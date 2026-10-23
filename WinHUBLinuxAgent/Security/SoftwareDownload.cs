using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace WinHUB.Security;

// The caller supplies the existing pinned, no-redirect, no-cookie agent HttpClient.
internal static class SoftwareDownload
{
    internal static Uri Resolve(string serverUrl, string path)
    {
        const string prefix = "/api/public/software-delivery/";
        if (!path.StartsWith(prefix, StringComparison.Ordinal) || !Guid.TryParseExact(path[prefix.Length..], "D", out _))
            throw new InvalidDataException("Invalid Software delivery path.");
        return ProductionSecurity.UpdateUri(serverUrl, path);
    }

    internal static async Task FetchAsync(HttpClient client, Uri uri, string token, long size, string sha256, string destination, CancellationToken cancellation)
    {
        if (size <= 0 || size > 16L * 1024 * 1024 * 1024 || sha256.Length != 64 || sha256.Any(c => !Uri.IsHexDigit(c)) || token.Length < 20 || token.Length > 256 || token.Any(char.IsControl))
            throw new InvalidDataException("Invalid Software package metadata.");
        while (true)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            request.Headers.TryAddWithoutValidation("Accept-Encoding", "identity");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation);
            if ((int)response.StatusCode == 429)
            {
                await Task.Delay(TimeSpan.FromSeconds(15), cancellation);
                continue;
            }
            if ((int)response.StatusCode != 200)
                throw new InvalidDataException($"Software download returned HTTP {(int)response.StatusCode}.");
            if (response.Content.Headers.ContentLength is long length && length != size)
                throw new InvalidDataException("Software package length differs from the signed task.");
            await using (var source = await response.Content.ReadAsStreamAsync(cancellation))
            await using (var output = File.Create(destination))
                await ProductionSecurity.CopyBoundedAsync(source, output, size, cancellation);
            using var stream = File.OpenRead(destination);
            var actual = SHA256.HashData(stream);
            if (stream.Length != size || !CryptographicOperations.FixedTimeEquals(actual, Convert.FromHexString(sha256)))
                throw new InvalidDataException("Software package size or SHA-256 mismatch.");
            return;
        }
    }
}
