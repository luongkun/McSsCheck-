using System;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using McSsCheck.Data;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

[SupportedOSPlatform("windows")]
internal static class RecycleBinScanner
{
    public const string SourceName = "RecycleBinScanner";

    /// <summary>
    /// Only consider Recycle Bin entries deleted within this window before the
    /// scan. The screenshare cheat-detection use case only cares about files
    /// the player wiped *just before* the SS started — old entries from
    /// uninstalled apps and forgotten downloads are noise that also makes the
    /// scan slow on machines that hoard a full Recycle Bin.
    ///
    /// Override per-run with <c>--recycle-window &lt;hours&gt;</c>; pass
    /// <c>0</c> to restore the legacy "scan everything" behaviour.
    /// </summary>
    public static double WindowHours { get; set; } = 24.0;

    public static void Run(SessionReport.Section section)
    {
        var windowHours = WindowHours;
        var cutoff = windowHours > 0
            ? DateTime.Now - TimeSpan.FromHours(windowHours)
            : DateTime.MinValue;

        var label = windowHours > 0
            ? $"Recycle Bin (jar / Minecraft files, deleted within last {windowHours:0.#}h)"
            : "Recycle Bin (jar / Minecraft files, full scan)";
        ConsoleUI.Section(label);

        var driveRoots = DriveInfo.GetDrives()
            .Where(d => d.IsReady && d.DriveType == DriveType.Fixed)
            .Select(d => Path.Combine(d.RootDirectory.FullName, "$Recycle.Bin"))
            .Where(Directory.Exists)
            .ToList();

        if (driveRoots.Count == 0)
        {
            ConsoleUI.Dim("No accessible $Recycle.Bin folders found (try running as admin if needed).");
            return;
        }

        int hits = 0, recent = 0, skipped = 0;
        foreach (var rb in driveRoots)
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(rb, "*", SearchOption.AllDirectories))
                {
                    var ext = Path.GetExtension(file);
                    if (string.IsNullOrEmpty(ext)) continue;
                    if (!ext.Equals(".jar", StringComparison.OrdinalIgnoreCase) &&
                        !ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) &&
                        !ext.Equals(".bat", StringComparison.OrdinalIgnoreCase) &&
                        !ext.Equals(".class", StringComparison.OrdinalIgnoreCase))
                        continue;

                    // Cheap stat call — Windows caches LastWriteTime, no FileInfo allocation needed.
                    DateTime mtime;
                    try { mtime = File.GetLastWriteTime(file); }
                    catch { skipped++; continue; }

                    if (mtime < cutoff)
                    {
                        skipped++;
                        continue;
                    }

                    recent++;
                    var nameHits = KnownCheats.MatchKeywords(file, KnownCheats.NameKeywords).ToList();
                    if (nameHits.Count > 0)
                    {
                        long size;
                        try { size = new FileInfo(file).Length; }
                        catch { size = -1; }

                        hits++;
                        ConsoleUI.Hit($"  recycle bin entry matches [{string.Join(",", nameHits)}]: {file}  size={size}  deleted~={mtime:yyyy-MM-dd HH:mm}");
                        section.Add(new ScanResult(
                            Source: SourceName, Severity: Severity.Hit,
                            Title: "Cheat-keyword binary in Recycle Bin",
                            Detail: $"size={size}, deleted~={mtime:yyyy-MM-dd HH:mm}, matched: {string.Join(", ", nameHits)}",
                            FilePath: file, Timestamp: mtime,
                            Tags: nameHits.ToArray()));
                    }
                    else
                    {
                        // Recent but not a cheat-keyword match — log to console only.
                        ConsoleUI.Dim($"  {file}  deleted~={mtime:yyyy-MM-dd HH:mm}");
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                ConsoleUI.Dim($"  (no access: {rb})");
            }
            catch (Exception ex)
            {
                ConsoleUI.Dim($"  (error reading {rb}: {ex.Message})");
            }
        }

        if (hits == 0)
        {
            if (windowHours > 0)
                ConsoleUI.Ok($"No cheat-keyword .jar/.exe/.bat/.class deletions in Recycle Bin within last {windowHours:0.#}h ({recent} recent, {skipped} older skipped).");
            else
                ConsoleUI.Ok($"No cheat-keyword .jar/.exe/.bat/.class entries in Recycle Bin ({recent} scanned).");
        }
    }
}
