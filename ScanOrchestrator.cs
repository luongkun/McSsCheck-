using System;
using System.Collections.Generic;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using McSsCheck.Models;
using McSsCheck.Reports;
using McSsCheck.Scanners;
using McSsCheck.Util;

namespace McSsCheck;

/// <summary>
/// Runs every enabled scanner in order against a fresh
/// <see cref="SessionReport"/>. Identical for both the console host and the
/// WinForms GUI host — the only difference is which <see cref="IUiSink"/>
/// is installed on <see cref="ConsoleUI"/> and which
/// <see cref="IProgressSink"/> is observing.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class ScanOrchestrator
{
    /// <summary>
    /// Run all enabled scanners and return the populated report.
    /// </summary>
    public static async Task<SessionReport> RunAsync(
        ScanOptions opts,
        IProgressSink progress,
        CancellationToken ct)
    {
        var report = new SessionReport { ToolVersion = Program.Version };

        // Push global per-scanner config from opts onto the static scanner state
        // before BuildSteps runs. Keep this list small — most scanners don't
        // need any tuning knobs.
        RecycleBinScanner.WindowHours = opts.RecycleWindowHours;

        var steps = BuildSteps(opts, report);
        progress.Begin(steps.Count);

        for (int i = 0; i < steps.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var (title, action) = steps[i];

            progress.StepStarted(title, i + 1, steps.Count);
            var section = report.StartSection(title);
            try
            {
                await action(section, ct);
            }
            catch (OperationCanceledException)
            {
                ConsoleUI.Warn($"{title}: cancelled");
                section.Add(new ScanResult(
                    Source: "Program", Severity: Severity.Warn,
                    Title: $"Section '{title}' cancelled",
                    Detail: "Cancellation requested by user."));
                progress.StepFinished(title, i + 1, steps.Count);
                throw;
            }
            catch (Exception ex)
            {
                ConsoleUI.Error($"{title}: {ex.GetType().Name}: {ex.Message}");
                section.Add(new ScanResult(
                    Source: "Program", Severity: Severity.Error,
                    Title: $"Section '{title}' crashed",
                    Detail: ex.ToString()));
            }
            progress.StepFinished(title, i + 1, steps.Count);
        }

        report.FinishedAt = DateTime.Now;
        ConsoleSummaryRenderer.Render(report);
        progress.Finished();
        return report;
    }

    private static List<(string Title, Func<SessionReport.Section, CancellationToken, Task> Action)>
        BuildSteps(ScanOptions opts, SessionReport report)
    {
        var s = new List<(string, Func<SessionReport.Section, CancellationToken, Task>)>();

        // ---- Sync scanners (wrapped to Task.CompletedTask) ----
        Func<Action<SessionReport.Section>, Func<SessionReport.Section, CancellationToken, Task>> sync =
            body => (sec, _) => { body(sec); return Task.CompletedTask; };

        if (!opts.NoPcInfo)    s.Add(("PC information",                    sync(sec => SystemInfoScanner.Run(report, sec))));
                                s.Add(("Java / Minecraft processes",       sync(sec => ProcessScanner.Run(sec))));
        if (!opts.NoLiveJvm)   s.Add(("Live JVM classpath",                sync(sec => LiveJvmScanner.Run(report, sec))));
                                s.Add(("Minecraft installations and mods", sync(sec => MinecraftScanner.Run(report, sec))));
        if (!opts.NoAccounts)  s.Add(("Alternative Minecraft accounts",    sync(sec => AltAccountScanner.Run(report, sec))));
        if (!opts.NoDiscord)   s.Add(("Discord accounts",                  sync(sec => DiscordAccountScanner.Run(report, sec))));
        if (!opts.NoRecycle)   s.Add(("Recycle Bin",                       sync(sec => RecycleBinScanner.Run(sec))));
        if (!opts.NoPrefetch)  s.Add(("Windows Prefetch",                  sync(sec => PrefetchScanner.Run(sec))));
        if (!opts.NoRegistry)  s.Add(("Registry artifacts",                sync(sec => RegistryScanner.Run(sec))));
        if (!opts.NoBrowser)   s.Add(("Browser history",                   sync(sec => BrowserHistoryScanner.Run(sec))));
        if (!opts.NoStartup)   s.Add(("Startup folder shortcuts",          sync(sec => StartupFolderScanner.Run(sec))));
        if (!opts.NoTasks)     s.Add(("Scheduled tasks",                   sync(sec => ScheduledTaskScanner.Run(sec))));
        if (!opts.NoRecent)    s.Add(("Recently-opened files",             sync(sec => RecentFilesScanner.Run(sec))));
        if (!opts.NoUsn)       s.Add(("NTFS USN journal (deleted files)",  sync(sec => UsnJournalScanner.Run(sec))));
        if (!opts.NoDefender)  s.Add(("Windows Defender history",          sync(sec => DefenderLogScanner.Run(sec))));
        if (!opts.NoEngines)   s.Add(("Heuristic engines",                 sync(sec => HeuristicEngineScanner.Run(report, sec))));
        if (!opts.NoAgentScan) s.Add(("Java-agent manifest scan",          sync(sec => JavaAgentScanner.Run(sec))));
        if (!opts.NoExeScan)   s.Add(("Renamed-cheat detector (hash + content markers)",
                                                                            sync(sec => CheatExeScanner.Run(sec))));

        // ---- Async network scanners ----
        s.Add(("Mods registry verification (Modrinth)",
            (sec, ct) => ModrinthChecker.RunAsync(report, sec, !opts.NoModrinth, ct)));

        if (!opts.NoVt)
            s.Add(("VirusTotal hash lookups",
                (sec, ct) => VirusTotalChecker.RunAsync(sec, opts.VtKey, ct)));

        return s;
    }
}
