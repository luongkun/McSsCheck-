using System;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using McSsCheck.Data;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

/// <summary>
/// Scans the per-user and all-users Startup folders for executables / scripts /
/// jars that auto-run when the user logs in. Cheat loaders sometimes put a
/// shortcut here so the player doesn't have to launch them manually before
/// joining a server.
///
/// Looks at:
///   * %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
///   * %ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup
///
/// The contents of every <c>.lnk</c> are parsed via Windows Script Host's
/// <c>WScript.Shell</c> COM object so that we can resolve the actual target
/// executable behind the shortcut. Read-only — no Startup folder is modified.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class StartupFolderScanner
{
    public const string SourceName = "StartupFolderScanner";

    public static void Run(SessionReport.Section section)
    {
        ConsoleUI.Section("Startup folder shortcuts");

        var folders = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        };

        int total = 0, hits = 0;
        foreach (var folder in folders.Where(f => !string.IsNullOrEmpty(f) && Directory.Exists(f)))
        {
            ConsoleUI.Info($"  scanning {folder}");
            string[] files;
            try
            {
                files = Directory.GetFiles(folder, "*", SearchOption.TopDirectoryOnly);
            }
            catch (Exception ex)
            {
                ConsoleUI.Warn($"  cannot list {folder}: {ex.Message}");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Warn,
                    Title: $"Startup folder access denied: {folder}",
                    Detail: ex.Message));
                continue;
            }

            foreach (var f in files)
            {
                total++;
                ProcessFile(section, f, ref hits);
            }
        }

        if (total == 0)
        {
            ConsoleUI.Ok("Startup folders are empty.");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Ok,
                Title: "Startup folders empty",
                Detail: "No shortcuts/scripts/jars found in user or all-users Startup."));
        }
        else if (hits == 0)
        {
            ConsoleUI.Ok($"Startup folders have {total} entries; none matched cheat keywords.");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Ok,
                Title: $"Startup folders clean ({total} entries)",
                Detail: "Found startup entries; none matched known cheat keywords."));
        }
    }

    private static void ProcessFile(SessionReport.Section section, string filePath, ref int hits)
    {
        var fname = Path.GetFileName(filePath);
        var lower = fname.ToLowerInvariant();

        // Resolve .lnk targets via WScript.Shell COM. If COM is unavailable,
        // we still flag .lnk by name keyword.
        string? lnkTarget = null;
        if (lower.EndsWith(".lnk"))
            lnkTarget = TryResolveShortcut(filePath);

        var matchTargets = new[] { fname, lnkTarget ?? "", filePath };

        var matched = matchTargets
            .SelectMany(t => KnownCheats.MatchKeywords(t, KnownCheats.NameKeywords))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        // .jar / .bat / .vbs / .ps1 in startup is unusual on its own.
        bool unusualExt = lower.EndsWith(".jar") || lower.EndsWith(".bat") ||
                          lower.EndsWith(".vbs") || lower.EndsWith(".ps1") ||
                          lower.EndsWith(".cmd");

        if (matched.Count > 0)
        {
            hits++;
            ConsoleUI.Hit($"  startup entry matches cheat keyword(s) [{string.Join(",", matched)}]: {filePath}");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Hit,
                Title: $"Startup entry matches cheat keyword: {fname}",
                Detail: $"file={filePath}\n" +
                        (lnkTarget != null ? $"target={lnkTarget}\n" : "") +
                        $"matched: {string.Join(", ", matched)}",
                FilePath: filePath,
                Tags: matched.Concat(new[] { "startup-folder" }).ToArray()));
        }
        else if (unusualExt)
        {
            ConsoleUI.Warn($"  startup entry has unusual extension: {filePath}");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Warn,
                Title: $"Startup entry has unusual extension: {fname}",
                Detail: $"file={filePath}",
                FilePath: filePath,
                Tags: new[] { "startup-folder" }));
        }
        else
        {
            ConsoleUI.Dim($"  startup entry: {fname}{(lnkTarget != null ? " -> " + lnkTarget : "")}");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Info,
                Title: $"Startup entry: {fname}",
                Detail: lnkTarget != null ? $"file={filePath}\ntarget={lnkTarget}" : $"file={filePath}",
                FilePath: filePath));
        }
    }

    /// <summary>
    /// Resolve a .lnk shortcut to its target path using the WScript.Shell COM
    /// object. Returns null if anything goes wrong (no COM, malformed lnk, etc.).
    /// </summary>
    private static string? TryResolveShortcut(string lnkPath)
    {
        try
        {
            var shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) return null;
            dynamic? shell = Activator.CreateInstance(shellType);
            if (shell == null) return null;
            try
            {
                dynamic shortcut = shell.CreateShortcut(lnkPath);
                try
                {
                    string? target = shortcut.TargetPath as string;
                    string? args   = shortcut.Arguments as string;
                    if (string.IsNullOrEmpty(target)) return null;
                    return string.IsNullOrEmpty(args) ? target : $"{target} {args}";
                }
                finally
                {
                    System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shortcut);
                }
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell);
            }
        }
        catch { return null; }
    }
}
