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

    public static void Run(SessionReport.Section section)
    {
        ConsoleUI.Section("Recycle Bin (jar / Minecraft files)");

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

        int total = 0;
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

                    total++;
                    var fi = new FileInfo(file);
                    var nameHits = KnownCheats.MatchKeywords(file, KnownCheats.NameKeywords).ToList();
                    if (nameHits.Count > 0)
                    {
                        ConsoleUI.Hit($"  recycle bin entry matches [{string.Join(",", nameHits)}]: {file}  size={fi.Length}  deleted~={fi.LastWriteTime:yyyy-MM-dd HH:mm}");
                        section.Add(new ScanResult(
                            Source: SourceName, Severity: Severity.Hit,
                            Title: "Cheat-keyword binary in Recycle Bin",
                            Detail: $"size={fi.Length}, deleted~={fi.LastWriteTime:yyyy-MM-dd HH:mm}, matched: {string.Join(", ", nameHits)}",
                            FilePath: file, Timestamp: fi.LastWriteTime,
                            Tags: nameHits.ToArray()));
                    }
                    else
                    {
                        ConsoleUI.Dim($"  {file}  size={fi.Length}  deleted~={fi.LastWriteTime:yyyy-MM-dd HH:mm}");
                        section.Add(new ScanResult(
                            Source: SourceName, Severity: Severity.Info,
                            Title: $"Recycle Bin entry: {Path.GetFileName(file)}",
                            Detail: $"size={fi.Length}, deleted~={fi.LastWriteTime:yyyy-MM-dd HH:mm}",
                            FilePath: file, Timestamp: fi.LastWriteTime));
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

        if (total == 0)
            ConsoleUI.Ok("No deleted .jar/.exe/.bat/.class files found in Recycle Bin.");
    }
}
