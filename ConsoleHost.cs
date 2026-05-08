using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using McSsCheck.Models;
using McSsCheck.Reports;
using McSsCheck.Util;

namespace McSsCheck;

/// <summary>
/// Legacy stdin/stdout host. Kept around behind <c>--console</c> so the
/// SS workflow that wants live colored stdout still works exactly like
/// before. Identical to pre-0.7.0 behavior aside from the orchestrator
/// extraction.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class ConsoleHost
{
    public static async Task<int> RunAsync(ScanOptions opts, bool autoYes, bool reportOnly)
    {
        // The default sink is already ConsoleUiSink; nothing to swap.

        ConsoleUI.Banner(
            $"McSsCheck v{Program.Version} — Minecraft screenshare helper (Windows)\n" +
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

        var report = await ScanOrchestrator.RunAsync(opts, NullProgressSink.Instance, CancellationToken.None);

        if (!opts.NoHtml)
        {
            try
            {
                var path = HtmlReportRenderer.RenderToFile(report, opts.HtmlPathArg);
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

    /// <summary>
    /// Attach a fresh console window to a process whose subsystem is
    /// <c>WinExe</c>. No-op when one is already attached (which happens when
    /// the .exe was launched from <c>cmd.exe</c> / PowerShell).
    /// </summary>
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AttachConsole(int processId);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool AllocConsole();
    private const int ATTACH_PARENT_PROCESS = -1;

    public static void EnsureConsoleAttached()
    {
        // Try to attach to the parent process's console (cmd / PowerShell);
        // if there's no parent console (double-clicked .exe), allocate a
        // brand new one.
        if (!AttachConsole(ATTACH_PARENT_PROCESS))
            AllocConsole();

        // Re-bind Console.Out / Console.In so they actually go to the new
        // console handles.
        var stdout = new System.IO.StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
        Console.SetOut(stdout);
        var stderr = new System.IO.StreamWriter(Console.OpenStandardError()) { AutoFlush = true };
        Console.SetError(stderr);
        var stdin = new System.IO.StreamReader(Console.OpenStandardInput());
        Console.SetIn(stdin);
    }
}
