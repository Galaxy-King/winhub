using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinHUB.Security;

internal sealed record ExecutionRecord(string Endpoint, string TaskId, string KeyId, long Sequence,
    string State, string Status, string Log);

[JsonSerializable(typeof(ExecutionRecord))]
internal partial class JournalJsonContext : JsonSerializerContext { }

// One agent process owns this directory. Never replay scripts after an ambiguous interruption.
// Completed entries are retained as small tombstones, not deleted on HTTP acknowledgement.
internal sealed class ExecutionJournal : IDisposable
{
    private const int MaxPending = 32;
    private const int MaxRecordBytes = 8 * 1024 * 1024;
    private readonly string directory;
    private readonly string endpoint;
    private readonly Action<string> protectFile;
    private readonly Action<string> protectDirectory;
    private readonly FileStream ownershipLock;
    private readonly Dictionary<string, string> states = new(StringComparer.Ordinal);

    internal ExecutionJournal(string directory, string endpoint, Action<string> protectFile, Action<string> protectDirectory)
    {
        ProductionSecurity.RejectLinks(directory);
        Directory.CreateDirectory(directory);
        protectDirectory(directory);
        this.directory = directory;
        this.endpoint = endpoint;
        this.protectFile = protectFile;
        this.protectDirectory = protectDirectory;
        string lockPath = Path.Combine(directory, ".owner.lock");
        ProductionSecurity.RejectLinks(lockPath);
        var options = new FileStreamOptions { Mode = FileMode.OpenOrCreate, Access = FileAccess.ReadWrite, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        ownershipLock = new FileStream(lockPath, options);
        try
        {
            protectFile(lockPath);
            string identityPath = Path.Combine(directory, ".endpoint");
            bool legacy = !File.Exists(identityPath);
            if (!legacy && ProductionSecurity.ReadText(identityPath, 1024) != endpoint)
                throw new InvalidDataException("Execution journal belongs to another endpoint.");
            if (legacy && Directory.Exists(Path.Combine(directory, "acknowledged")))
                throw new InvalidDataException("Archived journal identity is missing; restore it, do not regenerate it.");
            // Validate old flat records before binding identity. Migration is local and never executes a task.
            foreach (var record in Records(10000)) { }
            if (legacy) ProductionSecurity.AtomicWrite(identityPath, Encoding.UTF8.GetBytes(endpoint), protectFile);
            // Keep accepting the old flat layout after an interrupted migration, including when
            // the identity file was already committed. Only active entries consume the RAM budget.
            foreach (var record in Records(10000))
            {
                if (record.State == "acknowledged") Archive(record);
                else
                {
                    if (states.Count >= MaxPending) throw new InvalidDataException("Too many pending execution records.");
                    states.Add(record.TaskId, record.State);
                }
            }
        }
        catch { ownershipLock.Dispose(); throw; }
    }

    private string RecordPath(string taskId) => Path.Combine(directory,
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(taskId))).ToLowerInvariant() + ".json");

    private string ArchivedPath(string taskId)
    {
        string name = Path.GetFileName(RecordPath(taskId));
        return Path.Combine(directory, "acknowledged", name[..2], name);
    }

    private IEnumerable<ExecutionRecord> Records(int maximum)
    {
        int count = 0;
        foreach (string path in Directory.EnumerateFiles(directory, "*.json"))
        {
            if (++count > maximum) throw new InvalidDataException("Active execution journal capacity exceeded; preserve state for recovery.");
            yield return Read(path);
        }
    }

    private ExecutionRecord Read(string path)
    {
        var record = JsonSerializer.Deserialize(ProductionSecurity.ReadBytes(path, MaxRecordBytes), JournalJsonContext.Default.ExecutionRecord)
            ?? throw new InvalidDataException("Empty execution journal record.");
        if (record.Endpoint != endpoint || string.IsNullOrWhiteSpace(record.TaskId) || record.TaskId.Length > 256
            || record.Sequence <= 0 || record.KeyId == null || record.KeyId.Length != 64 || record.KeyId.Any(c => !Uri.IsHexDigit(c))
            || record.State is not ("claimed" or "result" or "acknowledged")
            || record.Status is not ("" or "Success" or "Error" or "Cancelled")
            || record.Log == null || (RecordPath(record.TaskId) != path && ArchivedPath(record.TaskId) != path))
            throw new InvalidDataException("Invalid execution journal; preserve it and recover with the administrator.");
        return record;
    }

    private void Write(ExecutionRecord record)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(record, JournalJsonContext.Default.ExecutionRecord);
        if (json.Length > MaxRecordBytes) throw new InvalidDataException("Execution result exceeds journal capacity.");
        ProductionSecurity.AtomicWrite(RecordPath(record.TaskId), json, protectFile);
        states[record.TaskId] = record.State;
    }

    private void Archive(ExecutionRecord record)
    {
        string archive = Path.Combine(directory, "acknowledged");
        string path = ArchivedPath(record.TaskId);
        ProductionSecurity.RejectLinks(path);
        foreach (string folder in new[] { archive, Path.GetDirectoryName(path)! })
        {
            Directory.CreateDirectory(folder);
            protectDirectory(folder);
        }
        if (OperatingSystem.IsLinux())
        {
            ProductionSecurity.FlushDirectory(directory);
            ProductionSecurity.FlushDirectory(archive);
        }
        // The durable tombstone MUST precede removal of the active record. A crash can leave
        // both copies, never neither; repeat migration/delivery is safe and does not rerun code.
        var tombstone = record with { State = "acknowledged", Log = "" };
        ProductionSecurity.AtomicWrite(path, JsonSerializer.SerializeToUtf8Bytes(tombstone, JournalJsonContext.Default.ExecutionRecord), protectFile);
        File.Delete(RecordPath(record.TaskId));
        if (OperatingSystem.IsLinux()) ProductionSecurity.FlushDirectory(directory);
        states.Remove(record.TaskId);
    }

    // Called only after cryptographic verification, BEFORE advancing the sequence and executing.
    internal void Claim(string taskId, string keyId, long sequence)
    {
        if (string.IsNullOrWhiteSpace(taskId) || taskId.Length > 256 || sequence <= 0
            || keyId == null || keyId.Length != 64 || keyId.Any(c => !Uri.IsHexDigit(c)))
            throw new InvalidDataException("Invalid task journal identity.");
        if (File.Exists(RecordPath(taskId))) throw new InvalidDataException("Task ID already claimed; execution is not repeated.");
        ProductionSecurity.RejectLinks(ArchivedPath(taskId));
        if (File.Exists(ArchivedPath(taskId)))
        {
            Read(ArchivedPath(taskId));
            throw new InvalidDataException("Task ID is already archived; execution is not repeated.");
        }
        if (states.Count >= MaxPending)
            throw new InvalidDataException("Execution journal is full; deliver pending results or request administrator maintenance.");
        Write(new(endpoint, taskId, keyId, sequence, "claimed", "", ""));
    }

    internal ExecutionRecord Complete(string taskId, string status, string log)
    {
        var record = Read(RecordPath(taskId));
        if (record.State != "claimed") throw new InvalidDataException("Task result has already been finalized locally.");
        if (status is not ("Success" or "Error" or "Cancelled")) throw new InvalidDataException("Invalid task result status.");
        var result = record with { State = "result", Status = status, Log = log };
        Write(result);
        return result;
    }

    // Startup only. There may have been side effects before termination: do not imply rollback or retry.
    internal void RecoverInterrupted()
    {
        foreach (string taskId in states.Where(entry => entry.Value == "claimed").Select(entry => entry.Key).ToList())
            Complete(taskId, "Error", "[WinHUB Agent] Execution outcome UNKNOWN after an interruption. The task may have partially executed. Automatic re-execution is forbidden; inspect the host before creating a new task.");
    }

    internal IEnumerable<ExecutionRecord> Pending() => states.Where(entry => entry.Value == "result")
        .Select(entry => Read(RecordPath(entry.Key))).OrderBy(record => record.Sequence).ToList();

    internal void Acknowledge(string taskId)
    {
        var record = Read(RecordPath(taskId));
        if (record.State != "result") throw new InvalidDataException("Only a completed result can be acknowledged.");
        Archive(record);
    }

    internal static bool IsSuccessAcknowledgement(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.TryGetProperty("status", out var status) && status.GetString() == "success";
    }

    public void Dispose() => ownershipLock.Dispose();
}
