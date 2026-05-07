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

        int relevant = 0;
        foreach (var pf in files.OrderByDescending(File.GetLastWriteTime))
        {
            var name = Path.GetFileName(pf);
            var lower = name.ToLowerInvariant();
            bool relevantExe = lower.StartsWith("java.exe-") || lower.StartsWith("javaw.exe-")
                               || lower.StartsWith("minecraft") || lower.Contains("launcher");
            var nameHits = KnownCheats.MatchKeywords(name, KnownCheats.NameKeywords).ToList();

            if (!relevantExe && nameHits.Count == 0) continue;

            var fi = new FileInfo(pf);
            relevant++;
            if (nameHits.Count > 0)
            {
                ConsoleUI.Hit($"  {name}  matches [{string.Join(",", nameHits)}]  last-run~={fi.LastWriteTime:yyyy-MM-dd HH:mm}");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Hit,
                    Title: $"Prefetch hit: {name}",
                    Detail: $"matched: {string.Join(", ", nameHits)}, last-run~={fi.LastWriteTime:yyyy-MM-dd HH:mm}",
                    FilePath: pf, Timestamp: fi.LastWriteTime,
                    Tags: nameHits.ToArray()));
            }
            else
            {
                ConsoleUI.Info($"  {name}  last-run~={fi.LastWriteTime:yyyy-MM-dd HH:mm}");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Info,
                    Title: $"Prefetch entry: {name}",
                    Detail: $"last-run~={fi.LastWriteTime:yyyy-MM-dd HH:mm}",
                    FilePath: pf, Timestamp: fi.LastWriteTime));
            }
        }

        if (relevant == 0)
            ConsoleUI.Ok("No Java/Minecraft-related Prefetch entries.");
    }
}
