using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.Versioning;
using McSsCheck.Data;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

/// <summary>
/// Hash- and content-based detector for renamed cheat clients.
///
/// The other scanners trust the file *name*: <c>vape.exe</c> matches because
/// it is literally named "vape". Players hide cheats by renaming
/// <c>atermys loader.exe</c> to <c>Anydesk.exe</c>, by repacking jars with
/// scrambled class names, etc. — the name-based scanners don't see those.
///
/// This scanner walks the player-controlled folders (Desktop, Downloads,
/// Documents, AppData, Temp, Public), and for every <c>.exe / .dll / .jar
/// / .zip</c>:
///   1. Computes the SHA-256 and looks it up in
///      <see cref="CheatFingerprints.KnownCheatHashes"/>.
///   2. Reads up to 8 MB of the raw bytes and runs
///      <see cref="BinaryMarkerScanner"/> against the binary markers
///      (PDB paths, branding banners, unique export names).
/// For .jar / .zip we also expand the archive in-memory and run the same
/// binary-marker pass against each interesting entry — this catches
/// agent-style cheats that ship encrypted blobs but still have one or two
/// distinctive plaintext strings inside their bootstrap class.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class CheatExeScanner
{
    public const string SourceName = "CheatExeScanner";

    /// <summary>Skip enormous files; cheats are never gigabytes.</summary>
    private const long MaxFileBytes = 200L * 1024 * 1024;

    /// <summary>
    /// Per-archive entry budget for content-marker matching. Cheat banners
    /// always live in the bootstrap / loader class which is small; reading
    /// 1 MB of every entry is wasteful.
    /// </summary>
    private const int PerEntryByteBudget = 256 * 1024;

    /// <summary>Per-archive: how many entries to peek inside.</summary>
    private const int MaxEntriesPerArchive = 64;

    public static void Run(SessionReport.Section section)
    {
        ConsoleUI.Section("Renamed-cheat detector (hash + binary markers)");

        var roots = CollectRoots();
        if (roots.Count == 0)
        {
            ConsoleUI.Dim("  no scoped folders found");
            return;
        }

        // Track which on-disk paths we've already inspected so a folder
        // appearing under multiple "roots" (e.g. %TEMP% == %LOCALAPPDATA%\Temp)
        // doesn't double-emit findings.
        var visitedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int totalFiles = 0, hashHits = 0, markerHits = 0;

        var exts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".jar", ".zip",
        };

        foreach (var root in roots)
        {
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.*", SearchOption.AllDirectories);
            }
            catch (Exception ex)
            {
                ConsoleUI.Dim($"  cannot enumerate {root}: {ex.Message}");
                continue;
            }

            foreach (var file in files)
            {
                if (!exts.Contains(Path.GetExtension(file))) continue;
                if (!visitedPaths.Add(file)) continue;

                FileInfo fi;
                try { fi = new FileInfo(file); }
                catch { continue; }
                if (fi.Length <= 0 || fi.Length > MaxFileBytes) continue;

                totalFiles++;

                // ---- Hash lookup ----
                string? sha256 = null;
                try { sha256 = HashUtil.Sha256OfFile(file); }
                catch (Exception ex)
                {
                    ConsoleUI.Dim($"  hash failed: {file}: {ex.Message}");
                }

                if (sha256 != null && CheatFingerprints.KnownCheatHashes.TryGetValue(sha256, out var label))
                {
                    hashHits++;
                    ConsoleUI.Hit($"  HASH: {label}  -> {file}");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Hit,
                        Title: $"Known cheat by SHA-256: {label}",
                        Detail: $"file={file}\nsha256={sha256}\nmatched: {label}",
                        FilePath: file, Hash: sha256,
                        Tags: new[] { "cheat-exe", "hash-match", LabelSlug(label) }));
                }

                // ---- Binary-marker scan ----
                List<BinaryMarkerScanner.MarkerHit> markers;
                try
                {
                    markers = ScanFileAndArchive(file).ToList();
                }
                catch (Exception ex)
                {
                    ConsoleUI.Dim($"  marker scan failed: {file}: {ex.Message}");
                    continue;
                }

                if (markers.Count == 0) continue;

                markerHits++;
                // Group markers by cheat name so one card per cheat per file.
                var grouped = markers
                    .GroupBy(m => m.CheatName, StringComparer.OrdinalIgnoreCase)
                    .ToList();

                foreach (var grp in grouped)
                {
                    var cheat = grp.Key;
                    var details = grp.Select(m => $"  - {m.Variant} ({m.Encoding}): \"{m.Pattern}\"")
                                     .Distinct()
                                     .ToArray();
                    var detail = $"file={file}\ncheat={cheat}\nmarkers:\n" + string.Join("\n", details);

                    ConsoleUI.Hit($"  MARKER: {cheat}  -> {file}  [{grp.Count()} marker(s)]");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Hit,
                        Title: $"Cheat content marker: {cheat}",
                        Detail: detail,
                        FilePath: file, Hash: sha256,
                        Tags: new[] { "cheat-exe", "marker-match", LabelSlug(cheat) }));
                }
            }
        }

        if (totalFiles == 0)
            ConsoleUI.Dim("  no candidate exe/dll/jar/zip files in scoped folders");
        else
            ConsoleUI.Info($"  scanned {totalFiles} file(s); hash hits={hashHits}, marker hits={markerHits}");
    }

    /// <summary>
    /// Pull the user-controlled folders we want to walk. Distinct() collapses
    /// the cases where %TEMP% and %LOCALAPPDATA%\Temp resolve to the same
    /// path, etc.
    /// </summary>
    private static List<string> CollectRoots()
    {
        var profile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var desktop  = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var docs     = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var appdata  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var local    = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var dl       = string.IsNullOrEmpty(profile) ? "" : Path.Combine(profile, "Downloads");
        var temp     = Path.GetTempPath();
        var pubDir   = Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public";

        var candidates = new[] { desktop, docs, dl, temp, pubDir, appdata, local, profile };

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var roots = new List<string>();
        foreach (var c in candidates)
        {
            if (string.IsNullOrEmpty(c)) continue;
            string norm;
            try { norm = Path.GetFullPath(c).TrimEnd('\\'); }
            catch { continue; }
            if (!Directory.Exists(norm)) continue;
            if (seen.Add(norm)) roots.Add(norm);
        }
        return roots;
    }

    /// <summary>
    /// Scan the file itself plus, when it's a zip / jar, up to the first
    /// <see cref="MaxEntriesPerArchive"/> compressed entries inside it.
    /// </summary>
    private static IEnumerable<BinaryMarkerScanner.MarkerHit> ScanFileAndArchive(string path)
    {
        var ext = Path.GetExtension(path);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Always scan the file as a flat blob first (catches PE / DLL strings
        // and cheats whose distinctive markers leak through the zip
        // central directory or unencrypted resources).
        foreach (var hit in BinaryMarkerScanner.ScanFile(path))
        {
            var key = $"{hit.CheatName}|{hit.Variant}";
            if (seen.Add(key)) yield return hit;
        }

        if (!string.Equals(ext, ".jar", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(ext, ".zip", StringComparison.OrdinalIgnoreCase))
            yield break;

        // Walk the archive entries; per-entry budget keeps us under control
        // on enormous fat-jar releases.
        ZipArchive zip;
        try
        {
            zip = ZipFile.OpenRead(path);
        }
        catch
        {
            yield break;
        }

        try
        {
            int scanned = 0;
            foreach (var entry in zip.Entries)
            {
                if (scanned >= MaxEntriesPerArchive) break;

                // Skip directories and obvious noise (audio / image / fonts).
                if (entry.Length == 0) continue;
                var entryExt = Path.GetExtension(entry.Name);
                if (entryExt is ".png" or ".jpg" or ".jpeg" or ".gif" or
                    ".ttf" or ".otf" or ".ogg" or ".mp3" or ".wav" or
                    ".webp" or ".ico") continue;

                scanned++;

                IReadOnlyList<BinaryMarkerScanner.MarkerHit> entryHits;
                try
                {
                    using var es = entry.Open();
                    entryHits = BinaryMarkerScanner.Scan(es, PerEntryByteBudget);
                }
                catch
                {
                    continue;
                }

                foreach (var hit in entryHits)
                {
                    var key = $"{hit.CheatName}|{hit.Variant}";
                    if (seen.Add(key)) yield return hit;
                }
            }
        }
        finally
        {
            zip.Dispose();
        }
    }

    private static string LabelSlug(string s)
    {
        var sb = new System.Text.StringBuilder(s.Length);
        foreach (var c in s.ToLowerInvariant())
            sb.Append(char.IsLetterOrDigit(c) ? c : '-');
        return sb.ToString().Trim('-');
    }
}
