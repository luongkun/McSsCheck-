using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.Versioning;
using McSsCheck.Data;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

[SupportedOSPlatform("windows")]
internal static class ProcessScanner
{
    public static void Run()
    {
        ConsoleUI.Section("Running Java / Minecraft processes");

        var entries = QueryJavaProcesses().ToList();
        if (entries.Count == 0)
        {
            ConsoleUI.Ok("No java.exe / javaw.exe processes are currently running.");
            return;
        }

        foreach (var p in entries)
        {
            ConsoleUI.Info($"PID {p.Pid}  {p.Name}  exe='{p.ExePath ?? "?"}'");
            if (!string.IsNullOrEmpty(p.CommandLine))
                ConsoleUI.Dim($"  cmdline: {Truncate(p.CommandLine, 400)}");

            // Flag suspicious -javaagent
            foreach (var agent in ExtractJavaAgents(p.CommandLine))
            {
                if (LooksSuspiciousAgentPath(agent))
                    ConsoleUI.Hit($"  -javaagent path looks unusual: {agent}");
                else
                    ConsoleUI.Warn($"  -javaagent: {agent}");
            }

            // Flag jars on cmdline that match known cheat keywords
            foreach (var token in TokenizeCmdline(p.CommandLine))
            {
                if (token.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
                {
                    var hits = KnownCheats.MatchKeywords(token, KnownCheats.NameKeywords).ToList();
                    if (hits.Count > 0)
                        ConsoleUI.Hit($"  jar on cmdline matches cheat keyword(s) [{string.Join(",", hits)}]: {token}");
                }
            }

            // Loaded modules (DLLs) — flag obviously off-path DLLs
            try
            {
                using var proc = Process.GetProcessById(p.Pid);
                foreach (ProcessModule mod in proc.Modules)
                {
                    var path = mod.FileName ?? string.Empty;
                    if (LooksSuspiciousModulePath(path))
                        ConsoleUI.Hit($"  loaded module from unusual path: {path}");
                }
            }
            catch (Exception ex)
            {
                ConsoleUI.Dim($"  (cannot enumerate modules: {ex.Message})");
            }
        }
    }

    private record ProcEntry(int Pid, string Name, string? ExePath, string? CommandLine);

    private static IEnumerable<ProcEntry> QueryJavaProcesses()
    {
        // WMI gives us the full command line, which Process API does not.
        const string query = "SELECT ProcessId, Name, ExecutablePath, CommandLine FROM Win32_Process " +
                             "WHERE Name = 'java.exe' OR Name = 'javaw.exe'";

        ManagementObjectCollection results;
        try
        {
            using var searcher = new ManagementObjectSearcher(query);
            results = searcher.Get();
        }
        catch (Exception ex)
        {
            ConsoleUI.Error($"WMI query failed: {ex.Message}");
            yield break;
        }

        foreach (ManagementObject mo in results)
        {
            int pid = Convert.ToInt32(mo["ProcessId"]);
            string name = mo["Name"] as string ?? "";
            string? exe = mo["ExecutablePath"] as string;
            string? cmd = mo["CommandLine"] as string;
            yield return new ProcEntry(pid, name, exe, cmd);
        }
    }

    private static IEnumerable<string> ExtractJavaAgents(string? cmd)
    {
        if (string.IsNullOrEmpty(cmd)) yield break;
        foreach (var tok in TokenizeCmdline(cmd))
        {
            if (tok.StartsWith("-javaagent:", StringComparison.OrdinalIgnoreCase))
                yield return tok.Substring("-javaagent:".Length);
        }
    }

    private static IEnumerable<string> TokenizeCmdline(string? cmd)
    {
        if (string.IsNullOrEmpty(cmd)) yield break;

        var current = new System.Text.StringBuilder();
        bool inQuotes = false;
        foreach (var c in cmd)
        {
            if (c == '"') { inQuotes = !inQuotes; continue; }
            if (char.IsWhiteSpace(c) && !inQuotes)
            {
                if (current.Length > 0) { yield return current.ToString(); current.Clear(); }
                continue;
            }
            current.Append(c);
        }
        if (current.Length > 0) yield return current.ToString();
    }

    private static bool LooksSuspiciousAgentPath(string path)
    {
        var lowered = path.ToLowerInvariant();
        string[] sus = { "\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "\\desktop\\", "\\public\\", "\\users\\public\\" };
        foreach (var s in sus) if (lowered.Contains(s)) return true;
        return false;
    }

    private static bool LooksSuspiciousModulePath(string modulePath)
    {
        if (string.IsNullOrEmpty(modulePath)) return false;
        var lowered = modulePath.ToLowerInvariant();

        // Whitelist obviously normal locations.
        if (lowered.Contains("\\windows\\system32\\")) return false;
        if (lowered.Contains("\\windows\\syswow64\\")) return false;
        if (lowered.Contains("\\program files\\")) return false;
        if (lowered.Contains("\\program files (x86)\\")) return false;
        if (lowered.Contains("\\java\\") || lowered.Contains("\\jre\\") || lowered.Contains("\\jdk\\")) return false;
        if (lowered.Contains("\\.minecraft\\")) return false;
        if (lowered.Contains("\\runtime\\")) return false;
        if (lowered.Contains("\\microsoft\\")) return false;

        // Otherwise, flag DLLs from unusual paths.
        if (lowered.EndsWith(".dll"))
        {
            string[] sus = { "\\temp\\", "\\downloads\\", "\\desktop\\", "\\users\\public\\", "\\appdata\\local\\temp\\" };
            foreach (var s in sus) if (lowered.Contains(s)) return true;
            // Generic catch: DLL not under any known runtime folder.
            return true;
        }
        return false;
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s.Substring(0, n) + "...";
}
