using System;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using McSsCheck.Models;
using McSsCheck.Reports;
using McSsCheck.Scanners;
using McSsCheck.Util;

namespace McSsCheck;

[SupportedOSPlatform("windows")]
internal static class Program
{
    private const string Version = "0.2.0";

    private static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("McSsCheck only supports Windows.");
            return 2;
        }

        bool autoYes        = false;
        bool noBrowser      = false;
        bool noRecycle      = false;
        bool noRegistry     = false;
        bool noPrefetch     = false;
        bool noUsn          = false;
        bool noDefender     = false;
        bool noVt           = false;
        bool noHtml         = false;
        bool reportOnly     = false;
        string? vtKey       = Environment.GetEnvironmentVariable("VT_API_KEY");
        string? htmlPathArg = null;

        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            switch (a)
            {
                case "-y":
                case "--yes":         autoYes      = true; break;
                case "--no-browser":  noBrowser    = true; break;
                case "--no-recycle":  noRecycle    = true; break;
                case "--no-registry": noRegistry   = true; break;
                case "--no-prefetch": noPrefetch   = true; break;
                case "--no-usn":      noUsn        = true; break;
                case "--no-defender": noDefender   = true; break;
                case "--no-vt":       noVt         = true; break;
                case "--no-html":     noHtml       = true; break;
                case "--report-only": reportOnly   = true; break;
                case "--vt-key":
                    if (i + 1 < args.Length) vtKey = args[++i];
                    else { Console.Error.WriteLine("--vt-key needs a value"); return 2; }
                    break;
                case "--html-path":
                    if (i + 1 < args.Length) htmlPathArg = args[++i];
                    else { Console.Error.WriteLine("--html-path needs a value"); return 2; }
                    break;
                case "-h":
                case "--help":
                    PrintUsage();
                    return 0;
                default:
                    Console.Error.WriteLine($"unknown arg: {a}");
                    PrintUsage();
                    return 2;
            }
        }

        ConsoleUI.Banner(
            $"McSsCheck v{Version} — Minecraft screenshare helper (Windows)\n" +
            "Local-only. No network calls except OPTIONAL VirusTotal hash lookup (only if you provide a key).\n" +
            "No file writes except an HTML report under your %TEMP% folder. No persistence.\n" +
            "Read-only checks: running Java/Minecraft processes, .minecraft folder, $Recycle.Bin,\n" +
            "Prefetch, registry MUICache+Run keys, browser history (cheat domains only),\n" +
            "NTFS USN journal (admin), Defender event log + DetectionHistory (admin), packed-jar heuristic.\n" +
            "Source: open. License: MIT.");

        if (!autoYes)
        {
            Console.Write("Player on this machine: type 'yes' to consent and start scanning, anything else aborts: ");
            var resp = Console.ReadLine();
            if (!string.Equals(resp?.Trim(), "yes", StringComparison.OrdinalIgnoreCase))
            {
                ConsoleUI.Error("Consent not given. Aborting.");
                return 1;
            }
        }

        var report = new SessionReport { ToolVersion = Version };

        // Sequence each scanner; failures are isolated.
        await RunSection(report, "Java / Minecraft processes",            s => ProcessScanner.Run(s));
        await RunSection(report, "Minecraft installations and mods",      s => MinecraftScanner.Run(s));
        if (!noRecycle)
            await RunSection(report, "Recycle Bin",                       s => RecycleBinScanner.Run(s));
        if (!noPrefetch)
            await RunSection(report, "Windows Prefetch",                  s => PrefetchScanner.Run(s));
        if (!noRegistry)
            await RunSection(report, "Registry artifacts",                s => RegistryScanner.Run(s));
        if (!noBrowser)
            await RunSection(report, "Browser history",                   s => BrowserHistoryScanner.Run(s));
        if (!noUsn)
            await RunSection(report, "NTFS USN journal (deleted files)",  s => UsnJournalScanner.Run(s));
        if (!noDefender)
            await RunSection(report, "Windows Defender history",          s => DefenderLogScanner.Run(s));
        if (!noVt)
        {
            var sec = report.StartSection("VirusTotal hash lookups");
            try { await VirusTotalChecker.RunAsync(sec, vtKey, CancellationToken.None); }
            catch (OperationCanceledException) { /* user cancelled, fine */ }
            catch (Exception ex) { ConsoleUI.Error($"VirusTotal section crashed: {ex.Message}"); }
        }

        report.FinishedAt = DateTime.Now;
        ConsoleSummaryRenderer.Render(report);

        if (!noHtml)
        {
            try
            {
                var path = HtmlReportRenderer.RenderToFile(report, htmlPathArg);
                ConsoleUI.Ok($"HTML report saved: {path}");
                HtmlReportRenderer.OpenInBrowser(path);
            }
            catch (Exception ex)
            {
                ConsoleUI.Error($"Could not write HTML report: {ex.Message}");
            }
        }

        if (!reportOnly)
        {
            ConsoleUI.Info("");
            ConsoleUI.Info("Scan complete. Press Enter to close this window.");
            try { Console.ReadLine(); } catch { /* console may not be interactive in CI */ }
        }
        return 0;
    }

    private static Task RunSection(SessionReport report, string title, Action<SessionReport.Section> body)
    {
        var section = report.StartSection(title);
        try { body(section); }
        catch (Exception ex)
        {
            ConsoleUI.Error($"{title}: {ex.GetType().Name}: {ex.Message}");
            section.Add(new ScanResult(
                Source: "Program",
                Severity: Severity.Error,
                Title: $"Section '{title}' crashed",
                Detail: ex.ToString()));
        }
        return Task.CompletedTask;
    }

    private static void PrintUsage()
    {
        Console.WriteLine($"McSsCheck v{Version}  —  usage:");
        Console.WriteLine("  McSsCheck.exe [flags]");
        Console.WriteLine("");
        Console.WriteLine("Flags:");
        Console.WriteLine("  -y, --yes          skip consent prompt (only when re-running after explicit consent)");
        Console.WriteLine("  --no-browser       skip browser-history scan");
        Console.WriteLine("  --no-recycle       skip Recycle Bin scan");
        Console.WriteLine("  --no-registry      skip registry scan");
        Console.WriteLine("  --no-prefetch      skip Prefetch scan");
        Console.WriteLine("  --no-usn           skip NTFS USN journal scan");
        Console.WriteLine("  --no-defender      skip Defender event log + DetectionHistory");
        Console.WriteLine("  --no-vt            skip VirusTotal hash lookups (also skipped if no key)");
        Console.WriteLine("  --no-html          do not generate / open the HTML report");
        Console.WriteLine("  --report-only      do not pause for Enter at the end");
        Console.WriteLine("  --vt-key <KEY>     VirusTotal v3 API key (alt: VT_API_KEY env var)");
        Console.WriteLine("  --html-path <P>    write HTML report to a specific file path");
        Console.WriteLine("  -h, --help         show this help");
    }
}
