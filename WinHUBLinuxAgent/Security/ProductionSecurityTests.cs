using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Diagnostics;
using System.IO.Compression;
using System.Formats.Tar;

namespace WinHUB.Security;

// Explicit offline self-test entry point only. No enrollment, real configuration, or production network access.
internal static class ProductionSecurityTests
{
    internal static void Run(Func<JsonElement, string> canonical)
    {
        int passed = 0;
        void Check(bool condition, string name)
        {
            if (!condition) throw new InvalidOperationException("Security self-test failed: " + name);
            passed++;
            Console.WriteLine("PASS " + name);
        }
        void Reject(Action action, string name)
        {
            try { action(); }
            catch (Exception ex) when (ex is InvalidDataException or CryptographicException or IOException or KeyNotFoundException or ArgumentException)
            { Check(true, name); return; }
            throw new InvalidOperationException("Security self-test accepted invalid input: " + name);
        }

        using RSA identity = RSA.Create(3072);
        using (var unicode = JsonDocument.Parse("{\"😀\":2,\"\\uE000\":1,\"text\":\"Привіт 😀\\n\"}"))
            Check(canonical(unicode.RootElement) == "{\"text\":\"Привіт 😀\\n\",\"\uE000\":1,\"😀\":2}", "Python-compatible Unicode values and property order");
        var request = new CertificateRequest("CN=winhub-offline-test", identity, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        using var expired = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-3), DateTimeOffset.UtcNow.AddDays(-2));
        string pin = certificate.GetCertHashString(HashAlgorithmName.SHA256);
        Check(ProductionSecurity.CertificateMatches(certificate, pin, null), "explicit self-signed certificate pin accepted");
        Check(!ProductionSecurity.CertificateMatches(certificate, new string('0', 64), null), "wrong pin rejected");
        Check(!ProductionSecurity.CertificateMatches(null, pin, null), "missing certificate rejected");
        Check(!ProductionSecurity.CertificateMatches(certificate, "", null), "no implicit trust on first use");
        Check(!ProductionSecurity.CertificateMatches(expired, expired.GetCertHashString(HashAlgorithmName.SHA256), null), "expired pinned certificate rejected");
        Check(ProductionSecurity.CertificateMatches(certificate, new string('0', 64), pin), "administrator-provisioned next pin accepted");
        Check(ProductionSecurity.ValidateConfiguration("https://winhub.test", pin, "", false, true).Host == "winhub.test", "strict config accepted");
        foreach (string url in new[] { "http://winhub.test", "https://user@winhub.test", "https://winhub.test/path", "https://winhub.test?token=secret", "https://winhub.test#other" })
            Reject(() => ProductionSecurity.ValidateConfiguration(url, pin, "", false, true), "unsafe URL rejected: " + url.Split('?')[0]);
        Reject(() => ProductionSecurity.ParsePin("SHA256=" + pin), "malformed pin cannot be silently normalized");
        Reject(() => ProductionSecurity.ValidateConfiguration("https://winhub.test", pin, "", true, true), "TLS bypass rejected");
        Reject(() => ProductionSecurity.ValidateConfiguration("https://winhub.test", pin, "", false, false), "signature bypass rejected");
        foreach (string url in new[] { "http://winhub.test/update.zip", "https://other.test/update.zip", "https://winhub.test:444/update.zip", "//other.test/update.zip" })
            Reject(() => ProductionSecurity.UpdateUri("https://winhub.test", url), "unsafe update origin rejected: " + url);
        Check(ProductionSecurity.UpdateUri("https://winhub.test", "/downloads/agent.zip").Host == "winhub.test", "relative update URL accepted");

        string Quote(string value) => "\"" + JsonEncodedText.Encode(value).ToString() + "\"";
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string MakeTask(string endpoint, long sequence, long issued, long expires)
        {
            const string payload = "{\"script\":\"echo hello\"}";
            using var payloadDoc = JsonDocument.Parse(payload);
            string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical(payloadDoc.RootElement)))).ToLowerInvariant();
            string keyId = Convert.ToHexString(SHA256.HashData(identity.ExportSubjectPublicKeyInfo())).ToLowerInvariant();
            string fields = $$"""{"protocol_version":2,"endpoint_id":{{Quote(endpoint)}},"task_id":"test-task","action":"run_script","payload_hash":"{{hash}}","timeout_seconds":300,"issued_at":{{issued}},"expires_at":{{expires}},"sequence":{{sequence}},"key_id":"{{keyId}}"}""";
            using var fieldsDoc = JsonDocument.Parse(fields);
            string signature = Convert.ToBase64String(identity.SignData(Encoding.UTF8.GetBytes(canonical(fieldsDoc.RootElement)), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
            return "{\"task_id\":\"test-task\",\"action\":\"run_script\",\"payload\":" + payload
                + ",\"timeout_seconds\":300,\"task_signature_v2\":{\"signature_alg\":\"rsa-pss-sha256\",\"fields\":" + fields
                + ",\"signature\":" + Quote(signature) + ",\"public_key_pem\":" + Quote(identity.ExportSubjectPublicKeyInfoPem()) + "}}";
        }
        void Verify(string json, string endpoint = "agent-a", long previous = 0, string key = "", string keyId = "")
        {
            using var doc = JsonDocument.Parse(json);
            TaskEnvelope.Verify(doc.RootElement, endpoint, key, keyId, previous, now, canonical);
        }
        string valid = MakeTask("agent-a", 7, now, now + 600);
        Verify(valid); Check(true, "valid RSA-PSS task accepted");
        Reject(() => Verify(valid, "agent-b"), "task for another endpoint rejected");
        Reject(() => Verify(valid, previous: 7), "repeated sequence rejected");
        Reject(() => Verify(valid, previous: 8), "older sequence rejected");
        Reject(() => Verify(valid.Replace("echo hello", "echo changed")), "changed script rejected");
        Reject(() => Verify(valid.Replace("\"timeout_seconds\":300", "\"timeout_seconds\":301")), "changed signed fields rejected");
        Reject(() => Verify(MakeTask("agent-a", 8, now - 1000, now - 1)), "expired signed task rejected");
        Reject(() => Verify(MakeTask("agent-a", 8, now + 301, now + 600)), "future task rejected");
        using RSA other = RSA.Create(3072);
        Reject(() => Verify(valid, key: other.ExportSubjectPublicKeyInfoPem()), "different pinned task key rejected");
        Reject(() => Verify("{\"signature\":\"legacy\"}"), "unsigned/legacy task rejected");

        string temporary = Path.Combine(Path.GetTempPath(), "winhub-security-selftest-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temporary);
        try
        {
            string state = Path.Combine(temporary, "state.json");
            Action<string> protect = path => { if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); };
            ProductionSecurity.AtomicWrite(state, Encoding.UTF8.GetBytes("old"), protect);
            Reject(() => ProductionSecurity.AtomicWrite(state, Encoding.UTF8.GetBytes("new"), _ => throw new IOException("simulated ACL failure")), "write/ACL failure propagates");
            Check(ProductionSecurity.ReadText(state) == "old", "failed write preserves previous state");
            ProductionSecurity.AtomicWrite(state, Encoding.UTF8.GetBytes("new"), protect);
            Check(ProductionSecurity.ReadText(state) == "new", "durable replacement readable after reopen");
            Reject(() => ProductionSecurity.ReadText(state, 2), "oversized state rejected");
            string hardwarePath = Path.Combine(temporary, "test.hwid");
            Reject(() => ProductionSecurity.HardwareIdentity(hardwarePath, true, () => "WINHUB-new", protect), "missing enrolled hardware identity does not silently regenerate");
            Check(ProductionSecurity.HardwareIdentity(hardwarePath, false, () => "WINHUB-test", protect) == "WINHUB-test", "new hardware identity persists atomically");
            Check(ProductionSecurity.HardwareIdentity(hardwarePath, true, () => "WINHUB-other", protect) == "WINHUB-test", "existing hardware identity retained");
            ProductionSecurity.AtomicWrite(hardwarePath, Encoding.UTF8.GetBytes("damaged"), protect);
            Reject(() => ProductionSecurity.HardwareIdentity(hardwarePath, false, () => "WINHUB-new", protect), "corrupt identity fails closed");

            string journalPath = Path.Combine(temporary, "execution-journal");
            string journalKey = new string('a', 64);
            using (var journal = new ExecutionJournal(journalPath, "agent-a", protect, _ => { }))
            {
                journal.Claim("task-one", journalKey, 1);
                Reject(() => journal.Claim("task-one", journalKey, 2), "duplicate task ID never executes again");
                Check(!journal.Pending().Any(), "claimed task has no invented result");
                journal.Complete("task-one", "Success", "saved output");
                Check(journal.Pending().Single().Log == "saved output", "result persists before delivery");
                Reject(() => journal.Complete("task-one", "Error", "replacement"), "completed result cannot be overwritten");
                Reject(() => { using var duplicate = new ExecutionJournal(journalPath, "agent-a", protect, _ => { }); }, "second agent cannot own execution journal");
                journal.Claim("interrupted", journalKey, 2);
            }
            using (var recovered = new ExecutionJournal(journalPath, "agent-a", protect, _ => { }))
            {
                recovered.RecoverInterrupted();
                Check(recovered.Pending().Count() == 2, "undelivered results survive agent restart");
                Check(recovered.Pending().Single(r => r.TaskId == "interrupted").Log.Contains("UNKNOWN"), "interrupted execution becomes unknown, not rerun");
                recovered.Acknowledge("task-one");
                Check(recovered.Pending().Count() == 1, "only acknowledged result leaves delivery queue");
                Reject(() => recovered.Claim("task-one", journalKey, 3), "acknowledged task tombstone prevents rerun");
            }
            Reject(() => { using var wrongEndpoint = new ExecutionJournal(journalPath, "agent-b", protect, _ => { }); }, "another endpoint cannot adopt execution journal");
            Check(ExecutionJournal.IsSuccessAcknowledgement("{\"status\":\"success\"}"), "server JSON success acknowledges result");
            Check(!ExecutionJournal.IsSuccessAcknowledgement("{\"status\":\"error\"}"), "HTTP 200 with error does not acknowledge result");
            string failedJournalPath = Path.Combine(temporary, "journal-write-failure");
            using (var failedJournal = new ExecutionJournal(failedJournalPath, "agent-a", path => { if (path.EndsWith(".tmp")) throw new IOException("simulated disk failure"); }, _ => { }))
                Reject(() => failedJournal.Claim("never-started", journalKey, 1), "failed durable claim prevents task execution");
            if (!OperatingSystem.IsWindows())
            {
                string link = Path.Combine(temporary, "link");
                File.CreateSymbolicLink(link, state);
                Reject(() => ProductionSecurity.AtomicWrite(link, Encoding.UTF8.GetBytes("bad"), protect), "symlink state rejected");
                File.Delete(link);
            }
            using var source = new MemoryStream(new byte[1025]);
            using var destination = new MemoryStream();
            Reject(() => ProductionSecurity.CopyBoundedAsync(source, destination, 1024, CancellationToken.None).GetAwaiter().GetResult(), "oversized streamed download rejected");
            using var output = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes(new string('x', 1025))));
            using var deadline = new CancellationTokenSource();
            Reject(() => ProductionSecurity.CaptureAsync(output, 1024, deadline).GetAwaiter().GetResult(), "oversized output rejected during capture");
            Check(deadline.IsCancellationRequested, "output overflow cancels task execution");

            string MakeZip(string entryName, string label, int attributes = 0)
            {
                string path = Path.Combine(temporary, label + ".zip");
                using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
                var entry = zip.CreateEntry(entryName);
                entry.ExternalAttributes = attributes;
                using var writer = new StreamWriter(entry.Open());
                writer.Write("fixture");
                return path;
            }
            string safeZip = MakeZip("folder/fixture.txt", "valid");
            SafeArchive.Extract(safeZip, Path.Combine(temporary, "valid-output"));
            Check(File.ReadAllText(Path.Combine(temporary, "valid-output", "folder", "fixture.txt")) == "fixture", "regular ZIP extracted");
            Reject(() => SafeArchive.Extract(MakeZip("../outside.txt", "traversal"), Path.Combine(temporary, "bad-path")), "ZIP traversal rejected");
            Reject(() => SafeArchive.Extract(MakeZip("link", "symlink", unchecked((int)0xA0000000)), Path.Combine(temporary, "bad-link")), "ZIP symlink rejected");
            Check(!File.Exists(Path.Combine(temporary, "outside.txt")), "no archive write outside staging");
            string safeTar = Path.Combine(temporary, "valid.tar.gz");
            using (var file = File.Create(safeTar))
            using (var gzip = new GZipStream(file, CompressionMode.Compress))
            using (var tar = new TarWriter(gzip))
            {
                var entry = new PaxTarEntry(TarEntryType.RegularFile, "./fixture.txt") { DataStream = new MemoryStream(Encoding.UTF8.GetBytes("fixture")) };
                tar.WriteEntry(entry);
            }
            SafeArchive.Extract(safeTar, Path.Combine(temporary, "tar-output"));
            Check(File.ReadAllText(Path.Combine(temporary, "tar-output", "fixture.txt")) == "fixture", "regular TAR.GZ extracted");

            var child = new ProcessStartInfo { UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true };
            if (OperatingSystem.IsWindows())
            {
                child.FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
                foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-Command", "[Console]::Write('x' * 8192)" }) child.ArgumentList.Add(argument);
            }
            else
            {
                child.FileName = "/bin/sh";
                child.ArgumentList.Add("-c");
                child.ArgumentList.Add("head -c 8192 /dev/zero");
            }
            bool limited = false;
            try { ProductionSecurity.RunCapturedAsync(child, 10, 1024, CancellationToken.None).GetAwaiter().GetResult(); }
            catch (Exception ex) when (ex is InvalidDataException or OperationCanceledException) { limited = true; }
            Check(limited, "real child process output is bounded");
            if (OperatingSystem.IsLinux())
            {
                string descendantPidPath = Path.Combine(temporary, "descendant.pid");
                var parent = new ProcessStartInfo("/bin/sh") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
                parent.ArgumentList.Add("-c");
                parent.ArgumentList.Add("sleep 120 & echo $! > '" + descendantPidPath.Replace("'", "'\"'\"'") + "'; exit 0");
                bool cancelled = false;
                try { ProductionSecurity.RunCapturedAsync(parent, 2, 1024, CancellationToken.None).GetAwaiter().GetResult(); }
                catch (OperationCanceledException) { cancelled = true; }
                int descendantPid = int.Parse(File.ReadAllText(descendantPidPath).Trim());
                string statusPath = $"/proc/{descendantPid}/stat";
                bool StillRunning()
                {
                    try
                    {
                        string stateText = File.ReadAllText(statusPath);
                        char processState = stateText[stateText.LastIndexOf(')') + 2];
                        return processState is not ('Z' or 'X');
                    }
                    catch (FileNotFoundException) { return false; }
                    catch (DirectoryNotFoundException) { return false; }
                }
                bool running = true;
                for (int attempt = 0; attempt < 20 && (running = StillRunning()); attempt++) Thread.Sleep(50);
                if (running) { using var descendant = Process.GetProcessById(descendantPid); descendant.Kill(); }
                Check(cancelled && !running, "Linux timeout kills descendant after original shell exits");
            }
        }
        finally { Directory.Delete(temporary, recursive: true); }
        Console.WriteLine($"Production security self-tests: {passed} passed. Live service/upgrade validation is separate.");
    }
}
