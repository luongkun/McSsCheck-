using System;
using System.Linq;
using System.Runtime.Versioning;
using McSsCheck.Scanners;
using McSsCheck.Util;

namespace McSsCheck;

[SupportedOSPlatform("windows")]
internal static class Program
{
    private const string Version = "0.1.0";

    public static int Main(string[] args)
    {
        bool noConfirm = args.Any(a => a is "--yes" or "-y");
        bool skipBrowser = args.Any(a => a is "--no-browser");
        bool skipRecycle = args.Any(a => a is "--no-recycle");
        bool skipReg     = args.Any(a => a is "--no-registry");
        bool skipPrefetch= args.Any(a => a is "--no-prefetch");

        if (args.Any(a => a is "--help" or "-h"))
        {
            PrintUsage();
            return 0;
        }

        ConsoleUI.Banner($"McSsCheck v{Version} — Minecraft screenshare helper");
        Console.WriteLine();
        Console.WriteLine("This tool scans the LOCAL machine for well-known Minecraft cheat-client artifacts.");
        Console.WriteLine("It is designed for consensual screenshare (SS) sessions on PvP/anarchy servers.");
        Console.WriteLine();
        Console.WriteLine("What it reads:");
        Console.WriteLine("  - Running java/javaw processes (command line, loaded modules)");
        Console.WriteLine("  - %APPDATA%\\.minecraft (mods, versions, resourcepacks, launcher_profiles.json)");
        Console.WriteLine("  - $Recycle.Bin                     (.jar/.exe/.bat/.class only)");
        Console.WriteLine("  - C:\\Windows\\Prefetch              (Java/Minecraft entries only)");
        Console.WriteLine("  - HKCU MUICache, Run keys, OpenSavePidlMRU\\jar");
        Console.WriteLine("  - Browser history (Chrome/Edge/Brave/Opera/Vivaldi/Firefox) — only checks");
        Console.WriteLine("    against a hardcoded list of cheat-client domains.");
        Console.WriteLine();
        Console.WriteLine("What it does NOT do:");
        Console.WriteLine("  - No network traffic, no upload, no telemetry, no persistence.");
        Console.WriteLine("  - No reading of passwords, cookies, sessions, documents, crypto wallets.");
        Console.WriteLine("  - No memory dump of arbitrary processes, no driver, no privilege escalation.");
        Console.WriteLine();
        Console.WriteLine("All results are printed to THIS console window only.");
        Console.WriteLine();

        if (!noConfirm)
        {
            Console.Write("Player confirms consent to scan this machine? Type 'yes' to continue: ");
            var line = Console.ReadLine();
            if (!string.Equals(line?.Trim(), "yes", StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine("No consent — exiting without scanning.");
                return 2;
            }
        }

        var startedAt = DateTime.Now;
        ConsoleUI.Info($"Scan started at {startedAt:yyyy-MM-dd HH:mm:ss zzz}");
        ConsoleUI.Info($"Hostname: {Environment.MachineName}  User: {Environment.UserName}  OS: {Environment.OSVersion}");

        SafeRun("ProcessScanner",     ProcessScanner.Run);
        SafeRun("MinecraftScanner",   MinecraftScanner.Run);
        if (!skipRecycle)  SafeRun("RecycleBinScanner", RecycleBinScanner.Run);
        if (!skipPrefetch) SafeRun("PrefetchScanner",    PrefetchScanner.Run);
        if (!skipReg)      SafeRun("RegistryScanner",    RegistryScanner.Run);
        if (!skipBrowser)  SafeRun("BrowserHistoryScanner", BrowserHistoryScanner.Run);

        var dt = DateTime.Now - startedAt;
        ConsoleUI.Banner($"Scan complete in {dt.TotalSeconds:F1}s — review [HIT] lines above with the player.");
        Console.WriteLine();
        Console.WriteLine("Press Enter to close.");
        Console.ReadLine();
        return 0;
    }

    private static void SafeRun(string name, Action body)
    {
        try { body(); }
        catch (Exception ex) { ConsoleUI.Error($"{name} crashed: {ex.GetType().Name}: {ex.Message}"); }
    }

    private static void PrintUsage()
    {
        Console.WriteLine($"McSsCheck v{Version}");
        Console.WriteLine();
        Console.WriteLine("Usage: McSsCheck.exe [flags]");
        Console.WriteLine();
        Console.WriteLine("  -y, --yes         Skip the consent prompt (only for automated reruns).");
        Console.WriteLine("      --no-browser  Skip browser history scan.");
        Console.WriteLine("      --no-recycle  Skip Recycle Bin scan.");
        Console.WriteLine("      --no-registry Skip registry MUICache/Run-key scan.");
        Console.WriteLine("      --no-prefetch Skip Windows Prefetch scan.");
        Console.WriteLine("  -h, --help        Show this message.");
    }
}
