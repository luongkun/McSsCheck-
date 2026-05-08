using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using McSsCheck.Data;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

[SupportedOSPlatform("windows")]
internal static class PrefetchScanner
{
    public const string SourceName = "PrefetchScanner";

    public static void Run(SessionReport.Section section)
    {
        ConsoleUI.Section("Windows Prefetch (recently launched executables)");

        var prefetch = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "Prefetch");

        if (!Directory.Exists(prefetch))
        {
            ConsoleUI.Dim($"Prefetch folder not present: {prefetch}");
            return;
        }

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(prefetch, "*.pf", SearchOption.TopDirectoryOnly);
        }
        catch (UnauthorizedAccessException)
        {
            ConsoleUI.Warn("No access to Prefetch — try running this tool elevated (Run as administrator).");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Warn,
                Title: "Prefetch not readable (run as admin)",
                Detail: prefetch));
            return;
        }

        // v0.8.0 noise cut: drop the "Severity.Info per minecraft/launcher prefetch" pathway
        // — those entries are typically WINWORD.EXE / ZALO.EXE / launcher.exe, not cheat-related.
        // Only emit Hits when the prefetch entry name actually matches a cheat keyword.
        int hits = 0, scanned = 0;
        foreach (var pf in files.OrderByDescending(File.GetLastWriteTime))
        {
            scanned++;
            var name = Path.GetFileName(pf);
            var nameHits = KnownCheats.MatchKeywords(name, KnownCheats.NameKeywords).ToList();
            if (nameHits.Count == 0) continue;

            var fi = new FileInfo(pf);
            hits++;
            ConsoleUI.Hit($"  {name}  matches [{string.Join(",", nameHits)}]  last-run~={fi.LastWriteTime:yyyy-MM-dd HH:mm}");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Hit,
                Title: $"Prefetch hit: {name}",
                Detail: $"matched: {string.Join(", ", nameHits)}, last-run~={fi.LastWriteTime:yyyy-MM-dd HH:mm}",
                FilePath: pf, Timestamp: fi.LastWriteTime,
                Tags: nameHits.ToArray()));
        }

        if (hits == 0)
            ConsoleUI.Ok($"No cheat-keyword Prefetch entries (scanned {scanned}).");
    }
}
