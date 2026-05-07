using System;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using McSsCheck.Data;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

[SupportedOSPlatform("windows")]
internal static class PrefetchScanner
{
    public static void Run()
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
            return;
        }

        int relevant = 0;
        foreach (var pf in files.OrderByDescending(File.GetLastWriteTime))
        {
            var name = Path.GetFileName(pf);
            // Prefetch filenames look like "JAVAW.EXE-1A2B3C4D.pf"
            var lower = name.ToLowerInvariant();
            bool relevantExe = lower.StartsWith("java.exe-") || lower.StartsWith("javaw.exe-")
                               || lower.StartsWith("minecraft") || lower.Contains("launcher");
            var nameHits = KnownCheats.MatchKeywords(name, KnownCheats.NameKeywords).ToList();

            if (!relevantExe && nameHits.Count == 0) continue;

            var fi = new FileInfo(pf);
            relevant++;
            if (nameHits.Count > 0)
                ConsoleUI.Hit($"  {name}  matches [{string.Join(",", nameHits)}]  last-run~={fi.LastWriteTime:yyyy-MM-dd HH:mm}");
            else
                ConsoleUI.Info($"  {name}  last-run~={fi.LastWriteTime:yyyy-MM-dd HH:mm}");
        }

        if (relevant == 0)
            ConsoleUI.Ok("No Java/Minecraft-related Prefetch entries.");
    }
}
