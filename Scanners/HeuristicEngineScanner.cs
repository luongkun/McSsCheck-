using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

/// <summary>
/// Ocean-style "engine" heuristics that run AFTER the regular scanners and
/// flag broad evasion / cleanup behaviours rather than specific cheat names:
///
///   * <b>GenericSelfDestruct</b>     – many .jar/.exe/.bat/.class files were
///                                      deleted recently (USN journal).
///   * <b>GenericBypassMethod</b>     – Prefetch directory is empty / very
///                                      sparse, OR Security/System event log
///                                      was cleared (event 1102 / 104).
///   * <b>AdsScriptStreamModification</b> – .bat / .cmd / .ps1 / .jar files
///                                      under common drop folders carry a
///                                      non-default NTFS Alternate Data
///                                      Stream (classic obfuscator trick).
///
/// All checks are read-only and require no admin (event log read needs admin
/// for the Security log; we degrade gracefully).
/// </summary>
[SupportedOSPlatform("windows")]
internal static class HeuristicEngineScanner
{
    public const string SourceName = "HeuristicEngineScanner";

    public static void Run(SessionReport report, SessionReport.Section section)
    {
        ConsoleUI.Section("Heuristic engines (SelfDestruct / Bypass / ADS)");

        try { GenericSelfDestruct(report, section); }
        catch (Exception ex) { ConsoleUI.Dim($"  GenericSelfDestruct error: {ex.Message}"); }

        try { GenericBypassMethod(section); }
        catch (Exception ex) { ConsoleUI.Dim($"  GenericBypassMethod error: {ex.Message}"); }

        try { AdsScriptStreamModification(section); }
        catch (Exception ex) { ConsoleUI.Dim($"  AdsScriptStreamModification error: {ex.Message}"); }
    }

    // -- Engine: GenericSelfDestruct -----------------------------------------------

    /// <summary>
    /// Counts how many recent USN-journal "deleted .jar/.exe/.bat/.class" warnings
    /// the previous USN scanner produced. If the count is higher than the threshold,
    /// flag a "Generic SelfDestruct" — the player wiped a lot of artifacts shortly
    /// before the screenshare.
    /// </summary>
    private static void GenericSelfDestruct(SessionReport report, SessionReport.Section section)
    {
        // v0.8.0: read the running tally directly from UsnJournalScanner.
        // Previously we re-scanned all sections looking for "Deleted binary on" /
        // "Deleted file matches" titles, but the per-file Warning cards have been
        // dropped to reduce report noise. We also still scan keyword-matched HIT
        // entries already added to the report so the sample list stays useful.
        int deletes = UsnJournalScanner.LastDeletedBinaryCount;
        var samples = new List<string>();
        foreach (var sec in report.Sections)
        {
            foreach (var r in sec.Results)
            {
                if (!string.Equals(r.Source, UsnJournalScanner.SourceName, StringComparison.Ordinal))
                    continue;
                if (samples.Count >= 5) break;
                if (!string.IsNullOrEmpty(r.FilePath))
                    samples.Add(r.FilePath);
            }
        }

        const int Threshold = 25;
        if (deletes >= Threshold)
        {
            ConsoleUI.Hit($"  GenericSelfDestruct: {deletes} jar/exe/bat/class deleted recently (sample: {string.Join(", ", samples)})");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Hit,
                Title: "Generic SelfDestruct",
                Detail: $"USN journal reports {deletes} recently-deleted .jar/.exe/.bat/.class files. "
                      + (samples.Count > 0 ? $"Sample: {string.Join(", ", samples)}." : ""),
                Tags: new[] { "engine", "selfdestruct" }));
        }
        else if (deletes > 0)
        {
            // Below threshold: keep this as console-only INFO (no card) — the report
            // already shows individual cheat-keyword Hits if they exist.
            ConsoleUI.Info($"  GenericSelfDestruct: {deletes} deleted (below threshold {Threshold}) — not flagged.");
        }
        else
        {
            ConsoleUI.Ok("  GenericSelfDestruct: no recent jar/exe/bat/class deletions detected.");
        }
    }

    // -- Engine: GenericBypassMethod -----------------------------------------------

    /// <summary>
    /// Flags two classic anti-forensic tricks:
    ///   - Prefetch wipe       (player cleared / disabled %WINDIR%\Prefetch)
    ///   - Event log cleared   (event 1102 in Security or 104 in System)
    /// </summary>
    private static void GenericBypassMethod(SessionReport.Section section)
    {
        // Prefetch sparseness
        try
        {
            var prefetch = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
            if (Directory.Exists(prefetch))
            {
                int pfCount = Directory.EnumerateFiles(prefetch, "*.pf", SearchOption.TopDirectoryOnly).Count();
                if (pfCount < 5)
                {
                    ConsoleUI.Hit($"  GenericBypassMethod: Prefetch contains {pfCount} entries (typical Win11 has 100+).");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Hit,
                        Title: "Generic Bypass Method (Prefetch wiped)",
                        Detail: $"%WINDIR%\\Prefetch only contains {pfCount} .pf entries. A clean Win10/11 install accumulates 100+ within the first hours of use; near-empty Prefetch typically means the player cleared it intentionally.",
                        FilePath: prefetch,
                        Tags: new[] { "engine", "bypass", "prefetch" }));
                }
            }
            else
            {
                ConsoleUI.Hit("  GenericBypassMethod: %WINDIR%\\Prefetch directory missing.");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Hit,
                    Title: "Generic Bypass Method (Prefetch directory missing)",
                    Detail: "%WINDIR%\\Prefetch not found. Either Superfetch is disabled or the player removed the folder; both severely reduce program-execution forensics.",
                    Tags: new[] { "engine", "bypass", "prefetch-missing" }));
            }
        }
        catch (Exception ex)
        {
            ConsoleUI.Dim($"  Prefetch check error: {ex.Message}");
        }

        // Event log cleared (Security event 1102, System event 104)
        bool elevated = IsElevated();
        try
        {
            CheckClearedLog("Security", 1102, section, requiresElevation: true, elevated);
            CheckClearedLog("System",   104,  section, requiresElevation: false, elevated);
            CheckClearedLog("Application", 104, section, requiresElevation: false, elevated);
        }
        catch (Exception ex)
        {
            ConsoleUI.Dim($"  EventLog check error: {ex.Message}");
        }
    }

    private static void CheckClearedLog(string logName, int eventId,
        SessionReport.Section section, bool requiresElevation, bool elevated)
    {
        if (requiresElevation && !elevated)
        {
            ConsoleUI.Dim($"  EventLog '{logName}' clear-check skipped (needs admin).");
            return;
        }
        try
        {
            var query = new EventLogQuery(logName, PathType.LogName, $"*[System/EventID={eventId}]")
            {
                ReverseDirection = true,
            };
            using var reader = new EventLogReader(query);
            EventRecord? rec = reader.ReadEvent();
            if (rec == null)
            {
                ConsoleUI.Ok($"  {logName}: never cleared (no event {eventId}).");
                return;
            }
            try
            {
                ConsoleUI.Hit($"  {logName} event log was cleared at {rec.TimeCreated:yyyy-MM-dd HH:mm}");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Hit,
                    Title: $"Generic Bypass Method ({logName} event log cleared)",
                    Detail: $"Event ID {eventId} present at {rec.TimeCreated:yyyy-MM-dd HH:mm}. Clearing the {logName} log is one of the few ways to hide program-launch traces.",
                    Timestamp: rec.TimeCreated,
                    Tags: new[] { "engine", "bypass", "event-log-cleared" }));
            }
            finally { rec.Dispose(); }
        }
        catch (UnauthorizedAccessException)
        {
            ConsoleUI.Dim($"  EventLog '{logName}' read denied (access).");
        }
        catch (EventLogNotFoundException)
        {
            // Some Windows editions don't have all logs
        }
    }

    // -- Engine: AdsScriptStreamModification ---------------------------------------

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindFirstStreamW(
        string lpFileName,
        int    InfoLevel,
        out    WIN32_FIND_STREAM_DATA lpFindStreamData,
        uint   dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindNextStreamW(
        IntPtr hFindStream,
        out WIN32_FIND_STREAM_DATA lpFindStreamData);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FindClose(IntPtr hFindFile);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WIN32_FIND_STREAM_DATA
    {
        public long StreamSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
        public string cStreamName;
    }

    private static void AdsScriptStreamModification(SessionReport.Section section)
    {
        var profile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var desktop  = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var docs     = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var dl       = Path.Combine(profile, "Downloads");
        var appdata  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var mc       = Path.Combine(appdata, ".minecraft");

        var roots = new[] { desktop, docs, dl, mc, profile }
            .Where(Directory.Exists).Distinct().ToList();

        var exts = new[] { ".bat", ".cmd", ".ps1", ".jar", ".vbs", ".js" };
        int scanned = 0, flagged = 0;

        foreach (var root in roots)
        {
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly);
            }
            catch (Exception ex)
            {
                ConsoleUI.Dim($"  cannot enumerate {root}: {ex.Message}");
                continue;
            }

            foreach (var file in files)
            {
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (Array.IndexOf(exts, ext) < 0) continue;

                scanned++;
                var streams = EnumerateAlternateStreams(file).ToList();
                if (streams.Count == 0) continue;

                flagged++;
                ConsoleUI.Hit($"  ADS on {file}: {string.Join(" | ", streams)}");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Hit,
                    Title: "ADS Script Stream Modification",
                    Detail: $"NTFS Alternate Data Stream(s) attached to '{Path.GetFileName(file)}': {string.Join(" | ", streams)}. ADS on script/jar files is a classic obfuscation trick used by cheat loaders.",
                    FilePath: file,
                    Tags: new[] { "engine", "ads", "ads-script" }));
            }
        }

        if (flagged == 0 && scanned > 0)
            ConsoleUI.Ok($"  AdsScriptStreamModification: scanned {scanned} script/jar file(s); no ADS found.");
        else if (scanned == 0)
            ConsoleUI.Dim("  AdsScriptStreamModification: no candidate script/jar files in scoped folders.");
    }

    private static IEnumerable<string> EnumerateAlternateStreams(string path)
    {
        IntPtr h = FindFirstStreamW(path, 0, out var data, 0);
        if (h == IntPtr.Zero || h.ToInt64() == -1) yield break;
        try
        {
            do
            {
                // Default data stream is "::$DATA"; anything else is alternate.
                if (!string.IsNullOrEmpty(data.cStreamName) &&
                    !data.cStreamName.Equals("::$DATA", StringComparison.Ordinal))
                {
                    yield return $"{data.cStreamName} ({data.StreamSize} bytes)";
                }
            } while (FindNextStreamW(h, out data));
        }
        finally { FindClose(h); }
    }

    // ---------------------------------------------------------------------------

    private static bool IsElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            var p = new WindowsPrincipal(id);
            return p.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }
}
