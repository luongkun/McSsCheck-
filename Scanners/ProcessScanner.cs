using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.Versioning;
using McSsCheck.Data;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

[SupportedOSPlatform("windows")]
internal static class ProcessScanner
{
    public const string SourceName = "ProcessScanner";

    public static void Run(SessionReport.Section section)
    {
        ConsoleUI.Section("Running Java / Minecraft processes");

        // --- External cheat loaders (Vape, Doomsday, Sigma external, etc.) ---
        ScanExternalLoaders(section);

        var entries = QueryJavaProcesses(section).ToList();
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

            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Info,
                Title: $"PID {p.Pid} {p.Name}",
                Detail: $"exe={p.ExePath}\ncmdline={p.CommandLine}"));

            foreach (var agent in ExtractJavaAgents(p.CommandLine))
            {
                bool sus = LooksSuspiciousAgentPath(agent);
                if (sus) ConsoleUI.Hit($"  -javaagent path looks unusual: {agent}");
                else     ConsoleUI.Warn($"  -javaagent: {agent}");
                section.Add(new ScanResult(
                    Source: SourceName,
                    Severity: sus ? Severity.Hit : Severity.Warn,
                    Title: sus ? "Suspicious -javaagent path" : "-javaagent declared",
                    Detail: $"PID {p.Pid}: -javaagent:{agent}",
                    FilePath: agent,
                    Tags: new[] { "javaagent", "active" }));
            }

            foreach (var token in TokenizeCmdline(p.CommandLine))
            {
                if (!token.EndsWith(".jar", StringComparison.OrdinalIgnoreCase)) continue;
                var hits = KnownCheats.MatchKeywords(token, KnownCheats.NameKeywords).ToList();
                if (hits.Count == 0) continue;
                ConsoleUI.Hit($"  jar on cmdline matches cheat keyword(s) [{string.Join(",", hits)}]: {token}");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Hit,
                    Title: "Cmdline jar matches cheat keyword",
                    Detail: $"PID {p.Pid} cmdline jar '{token}' matched: {string.Join(", ", hits)}",
                    FilePath: token,
                    Tags: hits.Concat(new[] { "active" }).ToArray()));
            }

            try
            {
                using var proc = Process.GetProcessById(p.Pid);
                foreach (ProcessModule mod in proc.Modules)
                {
                    var path = mod.FileName ?? string.Empty;
                    if (!LooksSuspiciousModulePath(path)) continue;
                    ConsoleUI.Hit($"  loaded module from unusual path: {path}");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Hit,
                        Title: "DLL loaded from unusual path",
                        Detail: $"PID {p.Pid} loaded {path}",
                        FilePath: path,
                        Tags: new[] { "module-injection", "active" }));
                }
            }
            catch (Exception ex)
            {
                ConsoleUI.Dim($"  (cannot enumerate modules: {ex.Message})");
            }
        }
    }

    /// <summary>
    /// Enumerate all running processes and match their names against
    /// <see cref="KnownCheats.ExternalCheatProcessNames"/>. These are
    /// standalone .exe cheat loaders (Vape v4, Doomsday, Sigma external,
    /// etc.) that inject into javaw rather than being a jar.
    /// </summary>
    private static void ScanExternalLoaders(SessionReport.Section section)
    {
        try
        {
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    var name = proc.ProcessName;
                    var matched = KnownCheats.MatchProcessName(name, KnownCheats.ExternalCheatProcessNames).ToList();
                    if (matched.Count == 0) continue;

                    string? exePath = null;
                    try { exePath = proc.MainModule?.FileName; } catch { /* access denied */ }

                    ConsoleUI.Hit($"  external cheat loader? PID {proc.Id} name={name} exe={exePath ?? "?"}  matched=[{string.Join(",", matched)}]");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Hit,
                        Title: $"External cheat loader detected: {name}.exe",
                        Detail: $"PID {proc.Id}, exe={exePath ?? "?"}, matched: {string.Join(", ", matched)}",
                        FilePath: exePath,
                        Tags: matched.Concat(new[] { "external-loader", "active" }).ToArray()));
                }
                catch { /* ignore individual process errors */ }
                finally { proc.Dispose(); }
            }
        }
        catch (Exception ex)
        {
            ConsoleUI.Dim($"  (external loader scan failed: {ex.Message})");
        }
    }

    private record ProcEntry(int Pid, string Name, string? ExePath, string? CommandLine);

    private static IEnumerable<ProcEntry> QueryJavaProcesses(SessionReport.Section section)
    {
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
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Error,
                Title: "WMI query failed",
                Detail: ex.Message));
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

        if (lowered.Contains("\\windows\\system32\\")) return false;
        if (lowered.Contains("\\windows\\syswow64\\")) return false;
        if (lowered.Contains("\\program files\\")) return false;
        if (lowered.Contains("\\program files (x86)\\")) return false;
        if (lowered.Contains("\\java\\") || lowered.Contains("\\jre\\") || lowered.Contains("\\jdk\\")) return false;
        if (lowered.Contains("\\.minecraft\\")) return false;
        if (lowered.Contains("\\runtime\\")) return false;
        if (lowered.Contains("\\microsoft\\")) return false;

        if (lowered.EndsWith(".dll"))
        {
            string[] sus = { "\\temp\\", "\\downloads\\", "\\desktop\\", "\\users\\public\\", "\\appdata\\local\\temp\\" };
            foreach (var s in sus) if (lowered.Contains(s)) return true;
            return true;
        }
        return false;
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s.Substring(0, n) + "...";
}
