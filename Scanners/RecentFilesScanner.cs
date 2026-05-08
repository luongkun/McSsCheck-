using System;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using McSsCheck.Data;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

/// <summary>
/// Scans the user's <c>%APPDATA%\Microsoft\Windows\Recent</c> folder for
/// recently-opened files. Windows updates these <c>.lnk</c> entries every time
/// the user double-clicks a document / executable / archive in Explorer, so
/// they often survive after the player deletes the original cheat jar /
/// installer / loader before screensharing.
///
/// We match each shortcut's filename against the cheat keyword list, and we
/// always flag <c>.jar</c> and <c>.exe</c> shortcuts as <c>INFO</c> for staff
/// to review.
///
/// Read-only — no shortcut is modified or deleted.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class RecentFilesScanner
{
    public const string SourceName = "RecentFilesScanner";

    private const int MaxEntriesToReport = 200;

    public static void Run(SessionReport.Section section)
    {
        ConsoleUI.Section("Recently-opened files (Windows Recent)");

        var folder = Environment.GetFolderPath(Environment.SpecialFolder.Recent);
        if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder))
        {
            ConsoleUI.Dim("Recent folder not found.");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Info,
                Title: "Recent folder not present",
                Detail: $"Expected: {folder}"));
            return;
        }

        string[] files;
        try
        {
            files = Directory.GetFiles(folder, "*.lnk", SearchOption.TopDirectoryOnly);
        }
        catch (Exception ex)
        {
            ConsoleUI.Warn($"  cannot list {folder}: {ex.Message}");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Warn,
                Title: "Recent folder access denied",
                Detail: ex.Message));
            return;
        }

        // Newest first so the top of the report is most actionable.
        Array.Sort(files, (a, b) =>
            File.GetLastWriteTimeUtc(b).CompareTo(File.GetLastWriteTimeUtc(a)));

        int hits = 0, jarLikeInfo = 0, processed = 0;
        foreach (var f in files)
        {
            if (processed >= MaxEntriesToReport) break;
            processed++;
            ProcessLnk(section, f, ref hits, ref jarLikeInfo);
        }

        if (files.Length == 0)
        {
            ConsoleUI.Ok("Recent folder is empty.");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Ok,
                Title: "Recent folder empty",
                Detail: "No .lnk shortcuts in %APPDATA%\\Microsoft\\Windows\\Recent."));
        }
        else if (hits == 0)
        {
            ConsoleUI.Ok($"Recent folder: {files.Length} entries, {jarLikeInfo} jar/exe; none matched cheat keywords.");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Ok,
                Title: $"Recent folder clean ({files.Length} entries)",
                Detail: $"{jarLikeInfo} of {files.Length} shortcuts pointed at .jar/.exe; none matched known cheat keywords."));
        }
    }

    private static void ProcessLnk(SessionReport.Section section, string lnkPath, ref int hits, ref int jarLikeInfo)
    {
        // The lnk filename itself usually has the form "<original>.<ext>.lnk"
        // (e.g. "wurst-7.40-fabric-mc1.20.4.jar.lnk"), which is a great
        // matching target on its own.
        var fname = Path.GetFileName(lnkPath);

        // Trim the trailing ".lnk" so .jar / .exe heuristics match cleanly.
        var displayName = fname.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)
            ? fname[..^4]
            : fname;
        var lower = displayName.ToLowerInvariant();

        bool jarLike = lower.EndsWith(".jar")  ||
                       lower.EndsWith(".exe")  ||
                       lower.EndsWith(".bat")  ||
                       lower.EndsWith(".cmd")  ||
                       lower.EndsWith(".class");
        if (jarLike) jarLikeInfo++;

        var matched = KnownCheats.MatchKeywords(displayName, KnownCheats.NameKeywords).ToList();
        DateTime mtime;
        try { mtime = File.GetLastWriteTime(lnkPath); }
        catch { mtime = DateTime.MinValue; }

        if (matched.Count > 0)
        {
            hits++;
            ConsoleUI.Hit($"  recent {fname} matches [{string.Join(",", matched)}]  mtime={mtime:yyyy-MM-dd HH:mm}");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Hit,
                Title: $"Recent shortcut matches cheat keyword: {displayName}",
                Detail: $"shortcut={lnkPath}\nopened~={mtime:yyyy-MM-dd HH:mm}\nmatched: {string.Join(", ", matched)}",
                FilePath: lnkPath, Timestamp: mtime,
                Tags: matched.Concat(new[] { "recent-files" }).ToArray()));
        }
        // v0.8.0 noise cut: drop the "Severity.Info per .jar/.exe shortcut" pathway.
        // Listing every WINWORD/ZALO/UNINSO000.EXE shortcut is noise — staff need
        // only know about shortcuts whose name actually matches a cheat keyword.
    }
}
