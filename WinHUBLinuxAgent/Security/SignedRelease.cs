using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace WinHUB.Security;

internal sealed record VerifiedRelease(long Serial, string Version, string ManifestHash, string Platform, string Architecture);
[JsonSerializable(typeof(VerifiedRelease))]
internal partial class ReleaseJsonContext : JsonSerializerContext { }

internal static class SignedRelease
{
    internal const string ManifestName = "release-manifest.json";
    internal const string TrustName = "release-signing-public.pem";
    internal const string StateName = "release-state.json";

    internal static VerifiedRelease VerifyDirectory(string directory, string trustFile, string stateFile,
        string platform, string architecture, string installedVersion, string expectedVersion)
    {
        using RSA key = RSA.Create();
        string trustedPem = ProductionSecurity.ReadText(trustFile, 32768).Trim();
        if (!trustedPem.StartsWith("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal)
            || !trustedPem.EndsWith("-----END PUBLIC KEY-----", StringComparison.Ordinal))
            throw new InvalidDataException("Provision only a public SPKI release key, never a private key.");
        key.ImportFromPem(trustedPem);
        if (key.KeySize < 3072 || key.KeySize > 8192) throw new InvalidDataException("Release signing key must be RSA 3072-8192 bits.");
        using var envelope = JsonDocument.Parse(ProductionSecurity.ReadBytes(Path.Combine(directory, ManifestName), 1024 * 1024));
        UniqueProperties(envelope.RootElement);
        if (envelope.RootElement.GetProperty("algorithm").GetString() != "rsa-pss-sha256")
            throw new InvalidDataException("Unsupported release signature algorithm.");
        byte[] payload = Convert.FromBase64String(envelope.RootElement.GetProperty("payload").GetString()!);
        byte[] signature = Convert.FromBase64String(envelope.RootElement.GetProperty("signature").GetString()!);
        if (payload.Length > 512 * 1024 || !key.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
            throw new InvalidDataException("Release publisher signature is invalid.");
        using var manifest = JsonDocument.Parse(payload);
        var root = manifest.RootElement;
        UniqueProperties(root);
        string keyId = Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
        if (root.GetProperty("schema").GetInt32() != 1 || root.GetProperty("key_id").GetString() != keyId
            || root.GetProperty("platform").GetString() != platform || root.GetProperty("architecture").GetString() != architecture)
            throw new InvalidDataException("Release targets a different platform, architecture or signing key.");
        string version = root.GetProperty("version").GetString()!;
        long serial = root.GetProperty("serial").GetInt64();
        if (serial <= 0 || CompareVersions(version, installedVersion) < 0
            || (!string.IsNullOrWhiteSpace(expectedVersion) && version != expectedVersion))
            throw new InvalidDataException("Release version mismatch or downgrade attempt.");
        var release = new VerifiedRelease(serial, version, Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant(), platform, architecture);
        CheckFloor(release, stateFile);
        var files = root.GetProperty("files");
        if (files.ValueKind != JsonValueKind.Array || files.GetArrayLength() is < 1 or > 4096)
            throw new InvalidDataException("Invalid release file inventory.");
        var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        long total = 0;
        foreach (var file in files.EnumerateArray())
        {
            UniqueProperties(file);
            string name = file.GetProperty("path").GetString()!;
            long size = file.GetProperty("size").GetInt64();
            if (string.IsNullOrWhiteSpace(name) || name.Length > 512 || name.StartsWith('/') || name.Contains('\\') || name.Contains(':')
                || name.Split('/').Any(part => part is "" or "." or ".." || part.EndsWith(' ') || part.EndsWith('.'))
                || name.Equals(ManifestName, StringComparison.OrdinalIgnoreCase) || !expected.Add(name)
                || size < 0 || size > ProductionSecurity.MaxUpdateBytes || (total += size) > 2L * 1024 * 1024 * 1024)
                throw new InvalidDataException("Invalid signed release file entry.");
            string path = Path.Combine(directory, name);
            ProductionSecurity.RejectLinks(path);
            using var stream = File.OpenRead(path);
            string hash = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
            if (stream.Length != size || hash != file.GetProperty("sha256").GetString())
                throw new InvalidDataException("Release file hash or size mismatch: " + name);
        }
        var directories = new Stack<string>();
        directories.Push(directory);
        int visited = 0;
        while (directories.TryPop(out string? current))
        {
            foreach (string path in Directory.EnumerateFileSystemEntries(current))
            {
                if (++visited > 8192) throw new InvalidDataException("Too many release inventory entries.");
                ProductionSecurity.RejectLinks(path);
                if (Directory.Exists(path)) { directories.Push(path); continue; }
                string name = Path.GetRelativePath(directory, path).Replace('\\', '/');
                if (name != ManifestName && !expected.Remove(name)) throw new InvalidDataException("Unsigned file in release package.");
            }
        }
        if (expected.Count != 0) throw new InvalidDataException("Signed files are missing from release package.");
        return release;
    }

    internal static void CheckFloor(VerifiedRelease candidate, string stateFile)
    {
        if (!File.Exists(stateFile)) return;
        var previous = JsonSerializer.Deserialize(ProductionSecurity.ReadBytes(stateFile, 8192), ReleaseJsonContext.Default.VerifiedRelease)
            ?? throw new InvalidDataException("Release anti-rollback state is invalid.");
        if (previous.Serial <= 0 || previous.ManifestHash == null || previous.ManifestHash.Length != 64
            || previous.ManifestHash.Any(c => !Uri.IsHexDigit(c)) || previous.Platform != candidate.Platform
            || previous.Architecture != candidate.Architecture || candidate.Serial < previous.Serial
            || CompareVersions(candidate.Version, previous.Version) < 0
            || (candidate.Serial == previous.Serial && candidate.ManifestHash != previous.ManifestHash))
            throw new InvalidDataException("Release anti-rollback floor rejected the package.");
    }

    internal static void Reserve(VerifiedRelease candidate, string stateFile, Action<string> protect)
    {
        CheckFloor(candidate, stateFile);
        ProductionSecurity.AtomicWrite(stateFile, JsonSerializer.SerializeToUtf8Bytes(candidate, ReleaseJsonContext.Default.VerifiedRelease), protect);
    }

    internal static VerifiedRelease VerifyPackage(string package, string dataDirectory, string platform, string architecture,
        string installedVersion, string expectedVersion, Action<string> protectFile, Action<string> protectDirectory)
    {
        // Missing publisher trust must not start extraction, reserve a floor or stop the service.
        ProductionSecurity.ReadBytes(Path.Combine(dataDirectory, TrustName), 32768);
        string staging = Path.Combine(dataDirectory, "updates", "verify-" + Guid.NewGuid().ToString("N"));
        ProductionSecurity.RejectLinks(staging);
        Directory.CreateDirectory(staging);
        protectDirectory(staging);
        try
        {
            SafeArchive.Extract(package, staging);
            string state = Path.Combine(dataDirectory, StateName);
            var release = VerifyDirectory(staging, Path.Combine(dataDirectory, TrustName), state, platform, architecture, installedVersion, expectedVersion);
            // Reserve before launch: a failed attempt can retry the SAME signed release,
            // but cannot silently lower the approved floor. Code rollback does not rewind this file.
            Reserve(release, state, protectFile);
            return release;
        }
        finally { ProductionSecurity.RejectLinks(staging); Directory.Delete(staging, recursive: true); }
    }

    internal static int CompareVersions(string left, string right)
    {
        string[] Parse(string value)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length > 128)
                throw new InvalidDataException("Invalid semantic release version.");
            value = value.Split('+')[0];
            if (!Regex.IsMatch(value, @"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$"))
                throw new InvalidDataException("Invalid semantic release version.");
            var parts = value.Split('-', 2);
            if (parts.Length == 2 && parts[1].Split('.').Any(p => p.All(char.IsAsciiDigit) && p.Length > 1 && p[0] == '0'))
                throw new InvalidDataException("Numeric prerelease identifiers cannot have leading zeros.");
            return parts;
        }
        static int Number(string a, string b) => a.Length != b.Length ? a.Length.CompareTo(b.Length) : string.CompareOrdinal(a, b);
        var a = Parse(left); var b = Parse(right);
        var an = a[0].Split('.'); var bn = b[0].Split('.');
        for (int i = 0; i < 3; i++)
        {
            int result = Number(an[i], bn[i]);
            if (result != 0) return result;
        }
        if (a.Length == 1 || b.Length == 1) return b.Length.CompareTo(a.Length);
        var ap = a[1].Split('.'); var bp = b[1].Split('.');
        for (int i = 0; i < Math.Min(ap.Length, bp.Length); i++)
        {
            bool ai = ap[i].All(char.IsAsciiDigit), bi = bp[i].All(char.IsAsciiDigit);
            if ((ai && ap[i].Length > 1 && ap[i][0] == '0') || (bi && bp[i].Length > 1 && bp[i][0] == '0'))
                throw new InvalidDataException("Numeric prerelease identifiers cannot have leading zeros.");
            int result = ai && bi ? Number(ap[i], bp[i]) : ai != bi ? (ai ? -1 : 1) : string.CompareOrdinal(ap[i], bp[i]);
            if (result != 0) return result;
        }
        return ap.Length.CompareTo(bp.Length);
    }

    private static void UniqueProperties(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Signed release JSON object required.");
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
            if (!names.Add(property.Name)) throw new InvalidDataException("Duplicate JSON property in signed release.");
    }
}
