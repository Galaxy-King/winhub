using System.Runtime.InteropServices;

namespace WinHUB.Security;

internal static class ReleaseCommand
{
    // Read-only diagnostics. Never call this flag on an older executable.
    internal static bool TryRun(string[] args, string platform)
    {
        if (args.Length == 0 || args[0] != "--verify-release") return false;
        try
        {
            if (args.Length != 6)
                throw new ArgumentException("Usage: --verify-release EXTRACTED_DIRECTORY TRUST_PEM STATE_PATH INSTALLED_VERSION EXPECTED_VERSION");
            var release = SignedRelease.VerifyDirectory(args[1], args[2], args[3], platform,
                RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(), args[4], args[5]);
            Console.WriteLine($"Release publisher signature and file inventory: OK; version={release.Version}; serial={release.Serial}. Read-only, no state changed.");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Release verification rejected: " + ex.Message);
            Environment.ExitCode = 1;
        }
        return true;
    }
}
