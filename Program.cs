using System;
using System.Linq;
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
    /// <summary>
    /// Tool version. Read once from the assembly so we don't have to keep three
    /// copies of the version string in sync (csproj / Program / SessionReport).
    /// </summary>
    public static readonly string Version = ResolveVersion();

    private static string ResolveVersion()
    {
        try
        {
            var asm = typeof(Program).Assembly;
            // Prefer InformationalVersion (set by csproj <InformationalVersion>) — that
            // is the human-readable "0.6.0" rather than the 0.6.0.0 file version.
            var info = asm
                .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
                .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
                .FirstOrDefault();
            if (info != null && !string.IsNullOrWhiteSpace(info.InformationalVersion))
            {
                // Strip any "+sha" build metadata suffix Source Link adds.
                var v = info.InformationalVersion;
                int plus = v.IndexOf('+');
                return plus > 0 ? v[..plus] : v;
            }
            return asm.GetName().Version?.ToString(3) ?? "0.0.0";
        }
        catch { return "0.0.0"; }
    }

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
        bool noPcInfo       = false;
        bool noAccounts     = false;
        bool noModrinth     = false;
        bool noLiveJvm      = false;
        bool noEngines      = false;
        bool noStartup      = false;
        bool noTasks        = false;
        bool noRecent       = false;
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
                case "--no-pcinfo":   noPcInfo     = true; break;
                case "--no-accounts": noAccounts   = true; break;
                case "--no-modrinth": noModrinth   = true; break;
                case "--no-livejvm":  noLiveJvm    = true; break;
                case "--no-engines":  noEngines    = true; break;
                case "--no-startup":  noStartup    = true; break;
                case "--no-tasks":    noTasks      = true; break;
                case "--no-recent":   noRecent     = true; break;
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
            "Local-only. Network calls are OPTIONAL: Modrinth hash verification (--no-modrinth disables)\n" +
            "and VirusTotal hash lookup (only if you provide --vt-key). No file writes except an HTML\n" +
            "report under your %TEMP% folder. No persistence.\n" +
            "Read-only checks: PC info, Java/Minecraft processes, LIVE JVM classpath (jars Minecraft is\n" +
            "loading right now), .minecraft, $Recycle.Bin, Prefetch, registry MUICache+Run keys, browser\n" +
            "history (cheat domains only), Startup folder, Scheduled tasks, Windows Recent shortcuts,\n" +
            "NTFS USN journal (admin), Defender event log + DetectionHistory (admin), packed-jar\n" +
            "heuristic, ADS / SelfDestruct / event-log-cleared engines, external cheat-loader process\n" +
            "names, alt MC accounts on disk, Discord install presence (NOT chat / token data).\n" +
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
        if (!noPcInfo)
            await RunSection(report, "PC information",                    s => SystemInfoScanner.Run(report, s));
        await RunSection(report, "Java / Minecraft processes",            s => ProcessScanner.Run(s));
        if (!noLiveJvm)
            await RunSection(report, "Live JVM classpath",                s => LiveJvmScanner.Run(report, s));
        await RunSection(report, "Minecraft installations and mods",      s => MinecraftScanner.Run(report, s));
        if (!noAccounts)
            await RunSection(report, "Alternative Minecraft accounts",    s => AltAccountScanner.Run(report, s));
        if (!noRecycle)
            await RunSection(report, "Recycle Bin",                       s => RecycleBinScanner.Run(s));
        if (!noPrefetch)
            await RunSection(report, "Windows Prefetch",                  s => PrefetchScanner.Run(s));
        if (!noRegistry)
            await RunSection(report, "Registry artifacts",                s => RegistryScanner.Run(s));
        if (!noBrowser)
            await RunSection(report, "Browser history",                   s => BrowserHistoryScanner.Run(s));
        if (!noStartup)
            await RunSection(report, "Startup folder shortcuts",          s => StartupFolderScanner.Run(s));
        if (!noTasks)
            await RunSection(report, "Scheduled tasks",                   s => ScheduledTaskScanner.Run(s));
        if (!noRecent)
            await RunSection(report, "Recently-opened files",             s => RecentFilesScanner.Run(s));
        if (!noUsn)
            await RunSection(report, "NTFS USN journal (deleted files)",  s => UsnJournalScanner.Run(s));
        if (!noDefender)
            await RunSection(report, "Windows Defender history",          s => DefenderLogScanner.Run(s));
        if (!noEngines)
            await RunSection(report, "Heuristic engines",                 s => HeuristicEngineScanner.Run(report, s));

        {
            var sec = report.StartSection("Mods registry verification (Modrinth)");
            try { await ModrinthChecker.RunAsync(report, sec, !noModrinth, CancellationToken.None); }
            catch (Exception ex) { ConsoleUI.Error($"Modrinth section crashed: {ex.Message}"); }
        }

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
        Console.WriteLine("  --no-pcinfo        skip PC information panel (system / hardware / VPN / Discord install)");
        Console.WriteLine("  --no-accounts      skip alternative Minecraft account scan");
        Console.WriteLine("  --no-modrinth      skip Modrinth jar verification (offline-only mode)");
        Console.WriteLine("  --no-livejvm       skip live JVM classpath inspection");
        Console.WriteLine("  --no-engines       skip heuristic engines (SelfDestruct / Bypass / ADS)");
        Console.WriteLine("  --no-startup       skip Startup folder scan");
        Console.WriteLine("  --no-tasks         skip Scheduled Task scan");
        Console.WriteLine("  --no-recent        skip Recent files scan");
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
