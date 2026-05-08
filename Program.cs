using System;
using System.Linq;
using System.Runtime.Versioning;
using System.Threading.Tasks;
using McSsCheck.Gui;
using McSsCheck.Models;

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

    [STAThread]
    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("McSsCheck only supports Windows.");
            return 2;
        }

        bool consoleMode    = false;
        bool autoYes        = false;
        bool reportOnly     = false;
        bool printHelp      = false;
        var  optsBuilder    = new OptsBuilder
        {
            VtKey = Environment.GetEnvironmentVariable("VT_API_KEY"),
        };

        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            switch (a)
            {
                case "--gui":         /* default, kept for explicitness */    break;
                case "--console":     consoleMode             = true;         break;
                case "-y":
                case "--yes":         autoYes                 = true;         break;
                case "--no-browser":  optsBuilder.NoBrowser   = true;         break;
                case "--no-recycle":  optsBuilder.NoRecycle   = true;         break;
                case "--no-registry": optsBuilder.NoRegistry  = true;         break;
                case "--no-prefetch": optsBuilder.NoPrefetch  = true;         break;
                case "--no-usn":      optsBuilder.NoUsn       = true;         break;
                case "--no-defender": optsBuilder.NoDefender  = true;         break;
                case "--no-vt":       optsBuilder.NoVt        = true;         break;
                case "--no-html":     optsBuilder.NoHtml      = true;         break;
                case "--no-pcinfo":   optsBuilder.NoPcInfo    = true;         break;
                case "--no-accounts": optsBuilder.NoAccounts  = true;         break;
                case "--no-modrinth": optsBuilder.NoModrinth  = true;         break;
                case "--no-livejvm":  optsBuilder.NoLiveJvm   = true;         break;
                case "--no-engines":  optsBuilder.NoEngines   = true;         break;
                case "--no-startup":  optsBuilder.NoStartup   = true;         break;
                case "--no-tasks":    optsBuilder.NoTasks     = true;         break;
                case "--no-recent":   optsBuilder.NoRecent    = true;         break;
                case "--report-only": reportOnly              = true;         break;
                case "--vt-key":
                    if (i + 1 < args.Length) optsBuilder.VtKey = args[++i];
                    else { return BadArg("--vt-key needs a value"); }
                    break;
                case "--html-path":
                    if (i + 1 < args.Length) optsBuilder.HtmlPathArg = args[++i];
                    else { return BadArg("--html-path needs a value"); }
                    break;
                case "-h":
                case "--help":        printHelp = true; break;
                default:
                    return BadArg($"unknown arg: {a}");
            }
        }

        var opts = optsBuilder.Build();

        // ---- console mode (legacy stdout streaming) -----------------------
        if (consoleMode || printHelp)
        {
            ConsoleHost.EnsureConsoleAttached();
            if (printHelp) { PrintUsage(); return 0; }
            return ConsoleHost.RunAsync(opts, autoYes, reportOnly).GetAwaiter().GetResult();
        }

        // ---- GUI mode (default) -------------------------------------------
        return GuiHost.Run(opts);
    }

    /// <summary>
    /// Tiny mutable struct that builds an immutable <see cref="ScanOptions"/>.
    /// </summary>
    private sealed class OptsBuilder
    {
        public bool NoBrowser, NoRecycle, NoRegistry, NoPrefetch, NoUsn, NoDefender;
        public bool NoVt, NoHtml, NoPcInfo, NoAccounts, NoModrinth, NoLiveJvm, NoEngines;
        public bool NoStartup, NoTasks, NoRecent;
        public string? VtKey;
        public string? HtmlPathArg;

        public ScanOptions Build() => new()
        {
            NoBrowser = NoBrowser, NoRecycle = NoRecycle, NoRegistry = NoRegistry,
            NoPrefetch = NoPrefetch, NoUsn = NoUsn, NoDefender = NoDefender,
            NoVt = NoVt, NoHtml = NoHtml, NoPcInfo = NoPcInfo,
            NoAccounts = NoAccounts, NoModrinth = NoModrinth, NoLiveJvm = NoLiveJvm,
            NoEngines = NoEngines, NoStartup = NoStartup, NoTasks = NoTasks,
            NoRecent = NoRecent, VtKey = VtKey, HtmlPathArg = HtmlPathArg,
        };
    }

    private static int BadArg(string msg)
    {
        ConsoleHost.EnsureConsoleAttached();
        Console.Error.WriteLine(msg);
        PrintUsage();
        return 2;
    }

    private static void PrintUsage()
    {
        Console.WriteLine($"McSsCheck v{Version}  —  usage:");
        Console.WriteLine("  McSsCheck.exe [flags]");
        Console.WriteLine("");
        Console.WriteLine("Mode:");
        Console.WriteLine("  --gui              Windows Forms GUI (default; no flag needed)");
        Console.WriteLine("  --console          legacy stdout/stdin console mode");
        Console.WriteLine("");
        Console.WriteLine("Flags:");
        Console.WriteLine("  -y, --yes          skip consent prompt (--console only; GUI uses an in-window button)");
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
        Console.WriteLine("  --report-only      console mode: do not pause for Enter at the end");
        Console.WriteLine("  --vt-key <KEY>     VirusTotal v3 API key (alt: VT_API_KEY env var)");
        Console.WriteLine("  --html-path <P>    write HTML report to a specific file path");
        Console.WriteLine("  -h, --help         show this help");
    }
}
