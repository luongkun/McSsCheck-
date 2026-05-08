using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using McSsCheck.Data;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

/// <summary>
/// Pulls Microsoft Defender malware-detection events out of two sources:
///  1. <c>Microsoft-Windows-Windows Defender/Operational</c> event log
///     (events 1006, 1007, 1015, 1116, 1117).
///  2. The on-disk DetectionHistory store under
///     <c>%ProgramData%\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\</c>.
/// Anything mentioning a Java / Minecraft / cheat-related path or detection name
/// is surfaced as a HIT.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class DefenderLogScanner
{
    public const string SourceName = "DefenderLogScanner";

    private static readonly int[] InterestingEventIds = { 1006, 1007, 1015, 1116, 1117 };

    public static void Run(SessionReport.Section section)
    {
        ConsoleUI.Section("Windows Defender / antivirus history");

        ScanEventLog(section);
        ScanDetectionHistoryFiles(section);
    }

    private static void ScanEventLog(SessionReport.Section section)
    {
        const string logName = "Microsoft-Windows-Windows Defender/Operational";
        try
        {
            var idClause = string.Join(" or ", InterestingEventIds.Select(i => $"EventID={i}"));
            var query = new EventLogQuery(logName, PathType.LogName, $"*[System[({idClause})]]");
            using var reader = new EventLogReader(query);

            int eventCount = 0;
            for (var ev = reader.ReadEvent(); ev != null; ev = reader.ReadEvent())
            {
                eventCount++;
                string desc;
                try { desc = ev.FormatDescription() ?? ""; }
                catch { desc = ""; }
                var when = ev.TimeCreated ?? DateTime.MinValue;

                var matchedKw = KnownCheats.MatchKeywords(desc, KnownCheats.NameKeywords).ToList();
                bool hasJavaJarHint = desc.Contains("java", StringComparison.OrdinalIgnoreCase) ||
                                      desc.Contains(".jar",  StringComparison.OrdinalIgnoreCase) ||
                                      desc.Contains("minecraft", StringComparison.OrdinalIgnoreCase);

                if (matchedKw.Count > 0)
                {
                    ConsoleUI.Hit($"  Defender event {ev.Id} @ {when:yyyy-MM-dd HH:mm}: matched [{string.Join(",", matchedKw)}]");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Hit,
                        Title: $"Defender event {ev.Id}: matched cheat keyword",
                        Detail: $"matched: {string.Join(", ", matchedKw)}\n\n{Truncate(desc, 800)}",
                        Timestamp: when, Tags: matchedKw.ToArray()));
                }
                else if (hasJavaJarHint)
                {
                    ConsoleUI.Warn($"  Defender event {ev.Id} @ {when:yyyy-MM-dd HH:mm}: mentions java/jar/minecraft");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Warn,
                        Title: $"Defender event {ev.Id} mentions java/jar/minecraft",
                        Detail: Truncate(desc, 800),
                        Timestamp: when));
                }

                ev.Dispose();
            }

            if (eventCount == 0)
                ConsoleUI.Ok("Defender event log: no malware/quarantine events.");
            else
                ConsoleUI.Info($"Defender event log: scanned {eventCount} event(s).");
        }
        catch (UnauthorizedAccessException)
        {
            ConsoleUI.Warn("No access to Defender event log — try running this tool as administrator.");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Warn,
                Title: "Defender event log not readable (run as admin)"));
        }
        catch (EventLogNotFoundException)
        {
            ConsoleUI.Dim("Defender event log not present (Defender disabled or replaced).");
        }
        catch (Exception ex)
        {
            ConsoleUI.Warn($"Defender event log error: {ex.Message}");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Error,
                Title: "Defender event log error",
                Detail: ex.Message));
        }
    }

    private static void ScanDetectionHistoryFiles(SessionReport.Section section)
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var historyDir = Path.Combine(programData,
            "Microsoft", "Windows Defender", "Scans", "History", "Service", "DetectionHistory");

        if (!Directory.Exists(historyDir))
        {
            ConsoleUI.Dim($"  no DetectionHistory folder ({historyDir})");
            return;
        }

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(historyDir, "*", SearchOption.AllDirectories);
        }
        catch (UnauthorizedAccessException)
        {
            ConsoleUI.Warn("  No access to DetectionHistory — try running this tool as administrator.");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Warn,
                Title: "Defender DetectionHistory not readable (run as admin)",
                FilePath: historyDir));
            return;
        }

        // The detection records on disk are a binary serialization, but they always
        // contain the file path & detection name as embedded UTF-16 strings.
        var stringFinder = new Regex(@"[\u0020-\u007e]{6,}", RegexOptions.Compiled);
        int hits = 0;
        foreach (var file in files)
        {
            byte[] bytes;
            try { bytes = File.ReadAllBytes(file); }
            catch { continue; }
            if (bytes.Length == 0) continue;

            // Decode as UTF-16 LE — DetectionHistory uses wide strings.
            string content;
            try { content = System.Text.Encoding.Unicode.GetString(bytes); }
            catch { continue; }

            var matchedKw = KnownCheats.MatchKeywords(content, KnownCheats.NameKeywords).ToList();
            bool hasJavaJarHint = content.Contains("java", StringComparison.OrdinalIgnoreCase) ||
                                  content.Contains(".jar",  StringComparison.OrdinalIgnoreCase) ||
                                  content.Contains("minecraft", StringComparison.OrdinalIgnoreCase);

            if (matchedKw.Count == 0 && !hasJavaJarHint) continue;

            // Pull a few human-readable strings as evidence.
            var evidence = stringFinder.Matches(content)
                .Cast<Match>()
                .Select(m => m.Value)
                .Where(v => v.Contains("java", StringComparison.OrdinalIgnoreCase) ||
                            v.Contains(".jar", StringComparison.OrdinalIgnoreCase) ||
                            v.Contains("minecraft", StringComparison.OrdinalIgnoreCase) ||
                            KnownCheats.MatchKeywords(v, KnownCheats.NameKeywords).Any())
                .Distinct()
                .Take(8)
                .ToList();

            var fi = new FileInfo(file);
            hits++;
            if (matchedKw.Count > 0)
            {
                ConsoleUI.Hit($"  DetectionHistory hit @ {fi.LastWriteTime:yyyy-MM-dd HH:mm}: matched [{string.Join(",", matchedKw)}]");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Hit,
                    Title: "Defender DetectionHistory: cheat keyword match",
                    Detail: $"matched: {string.Join(", ", matchedKw)}\n\nevidence:\n  - {string.Join("\n  - ", evidence)}",
                    FilePath: file, Timestamp: fi.LastWriteTime,
                    Tags: matchedKw.ToArray()));
            }
            else
            {
                ConsoleUI.Warn($"  DetectionHistory @ {fi.LastWriteTime:yyyy-MM-dd HH:mm}: mentions java/jar/minecraft");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Warn,
                    Title: "Defender DetectionHistory mentions java/jar/minecraft",
                    Detail: $"evidence:\n  - {string.Join("\n  - ", evidence)}",
                    FilePath: file, Timestamp: fi.LastWriteTime));
            }
        }

        if (hits == 0) ConsoleUI.Ok("DetectionHistory: no Java/Minecraft/cheat detections.");
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s.Substring(0, n) + "...";
}
