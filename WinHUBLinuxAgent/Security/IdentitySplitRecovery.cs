using System.Text;
using System.Text.Json.Nodes;
namespace WinHUB.Security;

internal static class IdentitySplitRecovery
{
    // Invoked only from a verified split command or its protected durable recovery state.
    internal static byte[] ResetTaskTrust(string configJson)
    {
        var config = JsonNode.Parse(configJson) as JsonObject ?? throw new InvalidDataException("Invalid split configuration.");
        config["TaskSigningPublicKeyPem"] = "";
        config["TaskSigningKeyId"] = "";
        config["TaskSigningLastSequence"] = 0;
        return Encoding.UTF8.GetBytes(config.ToJsonString());
    }
}
