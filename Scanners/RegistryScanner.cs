using System;
using System.Linq;
using System.Runtime.Versioning;
using Microsoft.Win32;
using McSsCheck.Data;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

[SupportedOSPlatform("windows")]
internal static class RegistryScanner
{
    public const string SourceName = "RegistryScanner";

    public static void Run(SessionReport.Section section)
    {
        ConsoleUI.Section("Registry: MUICache, Run keys, recently opened files");

        ScanMuiCache(section);
        ScanRunKeys(section);
        ScanOpenSavePidlMRU(section);
    }

    private static void ScanMuiCache(SessionReport.Section section)
    {
        const string path = @"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(path);
            if (key == null) { ConsoleUI.Dim($"  no MUICache key at HKCU\\{path}"); return; }

            int hits = 0;
            foreach (var name in key.GetValueNames())
            {
                var lower = name.ToLowerInvariant();
                bool relevant = lower.EndsWith(".exe.friendlyappname")
                                && (lower.Contains("java") || lower.Contains("minecraft") || lower.Contains("launcher"));
                var matched = KnownCheats.MatchKeywords(lower, KnownCheats.NameKeywords).ToList();

                if (!relevant && matched.Count == 0) continue;

                hits++;
                if (matched.Count > 0)
                {
                    ConsoleUI.Hit($"  MUICache hit [{string.Join(",", matched)}]: {name}");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Hit,
                        Title: "MUICache mentions cheat keyword",
                        Detail: $"value name: {name}; matched: {string.Join(", ", matched)}",
                        Tags: matched.ToArray()));
                }
                else
                {
                    ConsoleUI.Info($"  MUICache: {name}");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Info,
                        Title: "MUICache Java/Minecraft entry",
                        Detail: name));
                }
            }
            if (hits == 0) ConsoleUI.Ok("MUICache: no Java/Minecraft entries.");
        }
        catch (Exception ex)
        {
            ConsoleUI.Dim($"  MUICache error: {ex.Message}");
        }
    }

    private static void ScanRunKeys(SessionReport.Section section)
    {
        string[] runKeys =
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        };

        foreach (var path in runKeys)
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(path);
                if (key == null) continue;
                foreach (var name in key.GetValueNames())
                {
                    var val = key.GetValue(name)?.ToString() ?? "";
                    var matched = KnownCheats.MatchKeywords(val, KnownCheats.NameKeywords).ToList();
                    if (matched.Count > 0)
                    {
                        ConsoleUI.Hit($"  HKCU\\{path}!{name} -> {val}  hits=[{string.Join(",", matched)}]");
                        section.Add(new ScanResult(
                            Source: SourceName, Severity: Severity.Hit,
                            Title: "Run-key entry matches cheat keyword",
                            Detail: $"HKCU\\{path}!{name} -> {val}; matched: {string.Join(", ", matched)}",
                            Tags: matched.ToArray()));
                    }
                    else if (val.Contains("java", StringComparison.OrdinalIgnoreCase) ||
                             val.Contains(".jar", StringComparison.OrdinalIgnoreCase))
                    {
                        ConsoleUI.Warn($"  HKCU\\{path}!{name} -> {val}");
                        section.Add(new ScanResult(
                            Source: SourceName, Severity: Severity.Warn,
                            Title: "Java/.jar in Run key",
                            Detail: $"HKCU\\{path}!{name} -> {val}"));
                    }
                }
            }
            catch (Exception ex)
            {
                ConsoleUI.Dim($"  Run-key error ({path}): {ex.Message}");
            }
        }
    }

    private static void ScanOpenSavePidlMRU(SessionReport.Section section)
    {
        const string path = @"Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\jar";
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(path);
            if (key == null) { ConsoleUI.Dim("  no OpenSavePidlMRU\\jar key (no recent .jar pickers)"); return; }

            ConsoleUI.Info($"  OpenSavePidlMRU\\jar values: {key.ValueCount}  (binary PIDLs not decoded; presence implies recent .jar usage via dialogs)");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Warn,
                Title: "Recent .jar file pickers (OpenSavePidlMRU\\jar)",
                Detail: $"value count: {key.ValueCount} — user recently picked .jar files via Windows file dialogs"));
        }
        catch (Exception ex)
        {
            ConsoleUI.Dim($"  OpenSavePidlMRU error: {ex.Message}");
        }
    }
}
