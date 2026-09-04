using System.Formats.Tar;
using System.IO.Compression;

namespace WinHUB.Security;

internal static class SafeArchive
{
    internal static void Extract(string package, string destination)
    {
        ProductionSecurity.RejectLinks(destination);
        if (Directory.Exists(destination) && Directory.EnumerateFileSystemEntries(destination).Any())
            throw new IOException("Update staging directory must be empty.");
        Directory.CreateDirectory(destination);
        string root = Path.GetFullPath(destination).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        long total = 0;
        int entries = 0;
        string Target(string name, long size)
        {
            if (++entries > 4096 || size < 0 || size > ProductionSecurity.MaxUpdateBytes || (total += size) > 2L * 1024 * 1024 * 1024)
                throw new InvalidDataException("Expanded update package exceeds its limits.");
            name = name.Replace('\\', '/');
            while (name.StartsWith("./", StringComparison.Ordinal)) name = name[2..];
            if (name.Length > 512 || name.Contains(':') || Path.IsPathRooted(name)
                || name.Split('/').Any(part => part == ".." || part.EndsWith(' ') || (part != "." && part.EndsWith('.'))))
                throw new InvalidDataException("Invalid update archive path.");
            string target = Path.GetFullPath(Path.Combine(root, name));
            if (target.TrimEnd(Path.DirectorySeparatorChar) != root.TrimEnd(Path.DirectorySeparatorChar)
                && !target.StartsWith(root, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                throw new InvalidDataException("Archive entry escapes the staging directory.");
            return target;
        }
        using var source = File.OpenRead(package);
        if (package.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
        {
            using var zip = new ZipArchive(source, ZipArchiveMode.Read);
            foreach (var entry in zip.Entries)
            {
                int kind = (entry.ExternalAttributes >> 16) & 0xF000;
                if (kind != 0 && kind != 0x8000 && kind != 0x4000)
                    throw new InvalidDataException("Archive links and special files are forbidden.");
                string target = Target(entry.FullName, entry.Length);
                if (entry.FullName.EndsWith('/')) { Directory.CreateDirectory(target); continue; }
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                using var input = entry.Open();
                using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                ProductionSecurity.CopyBoundedAsync(input, output, entry.Length, CancellationToken.None).GetAwaiter().GetResult();
                if (output.Length != entry.Length) throw new InvalidDataException("Truncated archive entry.");
            }
        }
        else
        {
            using var gzip = new GZipStream(source, CompressionMode.Decompress);
            using var tar = new TarReader(gzip);
            TarEntry? entry;
            while ((entry = tar.GetNextEntry()) != null)
            {
                if (entry.EntryType is not (TarEntryType.Directory or TarEntryType.RegularFile or TarEntryType.V7RegularFile))
                    throw new InvalidDataException("Archive links and special files are forbidden.");
                string target = Target(entry.Name, entry.Length);
                if (entry.EntryType == TarEntryType.Directory) { Directory.CreateDirectory(target); continue; }
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                if (entry.DataStream != null)
                    ProductionSecurity.CopyBoundedAsync(entry.DataStream, output, entry.Length, CancellationToken.None).GetAwaiter().GetResult();
                if (output.Length != entry.Length) throw new InvalidDataException("Truncated archive entry.");
            }
        }
    }
}
