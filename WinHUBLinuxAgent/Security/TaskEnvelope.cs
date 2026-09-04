using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WinHUB.Security;

internal static class TaskEnvelope
{
    internal static readonly IComparer<string> PropertyComparer = Comparer<string>.Create((left, right) =>
    {
        var a = left.EnumerateRunes().GetEnumerator();
        var b = right.EnumerateRunes().GetEnumerator();
        while (true)
        {
            bool hasA = a.MoveNext(), hasB = b.MoveNext();
            if (!hasA || !hasB) return hasA ? 1 : hasB ? -1 : 0;
            int difference = a.Current.Value.CompareTo(b.Current.Value);
            if (difference != 0) return difference;
        }
    });

    internal static string Quote(string? value)
    {
        var builder = new StringBuilder("\"");
        foreach (char ch in value ?? "")
        {
            switch (ch)
            {
                case '"': builder.Append("\\\""); break;
                case '\\': builder.Append("\\\\"); break;
                case '\b': builder.Append("\\b"); break;
                case '\f': builder.Append("\\f"); break;
                case '\n': builder.Append("\\n"); break;
                case '\r': builder.Append("\\r"); break;
                case '\t': builder.Append("\\t"); break;
                default:
                    if (ch < 0x20) builder.Append("\\u").Append(((int)ch).ToString("x4"));
                    else builder.Append(ch);
                    break;
            }
        }
        return builder.Append('"').ToString();
    }

    internal static string Canonical(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.Object => "{" + string.Join(",", element.EnumerateObject()
            .OrderBy(p => p.Name, PropertyComparer).Select(p => Quote(p.Name) + ":" + Canonical(p.Value))) + "}",
        JsonValueKind.Array => "[" + string.Join(",", element.EnumerateArray().Select(Canonical)) + "]",
        JsonValueKind.String => Quote(element.GetString()),
        JsonValueKind.Number => element.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Null => "null",
        _ => throw new InvalidDataException("Invalid JSON value in signed envelope.")
    };

    internal static (string PublicKey, string KeyId, long Sequence) Verify(JsonElement task, string endpoint,
        string pinnedKey, string pinnedKeyId, long lastSequence, long now, Func<JsonElement, string> canonical)
    {
        JsonElement envelope = task.GetProperty("task_signature_v2");
        JsonElement fields = envelope.GetProperty("fields");
        if (envelope.GetProperty("signature_alg").GetString() != "rsa-pss-sha256")
            throw new CryptographicException("Unsupported task signature algorithm.");
        string publicKey = string.IsNullOrWhiteSpace(pinnedKey) ? envelope.GetProperty("public_key_pem").GetString()! : pinnedKey;
        if (publicKey == null || publicKey.Length > 8192) throw new CryptographicException("Invalid task signing public key.");
        string keyId = fields.GetProperty("key_id").GetString()!;
        long sequence = fields.GetProperty("sequence").GetInt64();
        long issued = fields.GetProperty("issued_at").GetInt64();
        long expires = fields.GetProperty("expires_at").GetInt64();
        string taskId = task.GetProperty("task_id").GetString()!;
        int timeout = task.GetProperty("timeout_seconds").GetInt32();
        string payloadHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical(task.GetProperty("payload"))))).ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(endpoint) || string.IsNullOrWhiteSpace(taskId) || taskId.Length > 256
            || fields.GetProperty("protocol_version").GetInt32() != 2
            || fields.GetProperty("endpoint_id").GetString() != endpoint
            || fields.GetProperty("task_id").GetString() != taskId
            || fields.GetProperty("action").GetString() != task.GetProperty("action").GetString()
            || fields.GetProperty("timeout_seconds").GetInt32() != timeout
            || fields.GetProperty("payload_hash").GetString() != payloadHash
            || timeout < 1 || timeout > 86400 || issued <= 0 || issued > now + 300
            || expires < now || expires < issued || expires - issued > 86400 || sequence <= lastSequence)
            throw new CryptographicException("Task address, content, expiry or replay sequence is invalid.");
        using RSA rsa = RSA.Create();
        rsa.ImportFromPem(publicKey);
        if (rsa.KeySize < 3072 || rsa.KeySize > 8192) throw new CryptographicException("Unsupported task key strength.");
        string actualId = Convert.ToHexString(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
        if (actualId != keyId || (!string.IsNullOrWhiteSpace(pinnedKeyId) && keyId != pinnedKeyId))
            throw new CryptographicException("Task signing key does not match the pinned key.");
        string signature = envelope.GetProperty("signature").GetString()!;
        if (signature == null || signature.Length > 2048 || !rsa.VerifyData(Encoding.UTF8.GetBytes(canonical(fields)),
            Convert.FromBase64String(signature), HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
            throw new CryptographicException("Task signature is invalid.");
        return (publicKey, keyId, sequence);
    }
}
