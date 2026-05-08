using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Xml;
using McSsCheck.Data;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

/// <summary>
/// Enumerates Windows scheduled tasks by reading the on-disk task XML under
/// <c>%SystemRoot%\System32\Tasks</c>. Cheat loaders occasionally install a
/// scheduled task as a persistence mechanism (e.g. "run loader at logon").
///
/// Looks at:
///   * the task name / file path
///   * the <c>Actions/Exec/Command</c> element (the actual binary that runs)
///   * the <c>Actions/Exec/Arguments</c> element (any cmdline)
///
/// Read-only — we never invoke <c>schtasks</c>'s mutating verbs. If the
/// process can't read the Tasks folder (admin tasks need elevation), we
/// skip those entries gracefully.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class ScheduledTaskScanner
{
    public const string SourceName = "ScheduledTaskScanner";

    public static void Run(SessionReport.Section section)
    {
        ConsoleUI.Section("Scheduled tasks (cheat persistence check)");

        var taskRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "Tasks");

        if (!Directory.Exists(taskRoot))
        {
            ConsoleUI.Warn($"Tasks folder not found: {taskRoot}");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Warn,
                Title: "Tasks folder not found",
                Detail: $"Expected: {taskRoot}"));
            return;
        }

        int total = 0, hits = 0, accessDenied = 0;

        foreach (var f in EnumerateTaskFilesSafe(taskRoot))
        {
            total++;
            try
            {
                ProcessTaskFile(section, taskRoot, f, ref hits);
            }
            catch (UnauthorizedAccessException)
            {
                accessDenied++;
            }
            catch (IOException)
            {
                accessDenied++;
            }
            catch (Exception ex)
            {
                ConsoleUI.Dim($"  cannot parse {f}: {ex.Message}");
            }
        }

        if (accessDenied > 0)
        {
            ConsoleUI.Warn($"  {accessDenied} task file(s) inaccessible (likely admin-only).");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Warn,
                Title: $"{accessDenied} scheduled task(s) inaccessible",
                Detail: "Some task XML files require admin to read. Re-run elevated for full coverage."));
        }

        if (total == 0)
        {
            ConsoleUI.Ok("No scheduled task files found.");
        }
        else if (hits == 0)
        {
            ConsoleUI.Ok($"Read {total} scheduled task(s); none matched cheat keywords.");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Ok,
                Title: $"Scheduled tasks clean ({total} read)",
                Detail: "No task name / command / arguments matched known cheat keywords."));
        }
    }

    private static IEnumerable<string> EnumerateTaskFilesSafe(string root)
    {
        // Walk manually because GetFiles(SearchOption.AllDirectories) bails out
        // on the FIRST UnauthorizedAccessException — we want partial coverage.
        var stack = new Stack<string>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            var dir = stack.Pop();

            string[] files;
            try { files = Directory.GetFiles(dir); }
            catch { files = Array.Empty<string>(); }
            foreach (var f in files) yield return f;

            string[] subs;
            try { subs = Directory.GetDirectories(dir); }
            catch { subs = Array.Empty<string>(); }
            foreach (var s in subs) stack.Push(s);
        }
    }

    private static void ProcessTaskFile(SessionReport.Section section, string root, string filePath,
                                        ref int hits)
    {
        // Friendly task name = relative path under \Tasks\.
        string relName = filePath.Length > root.Length
            ? filePath.Substring(root.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            : Path.GetFileName(filePath);

        XmlDocument xml;
        try
        {
            xml = new XmlDocument();
            xml.Load(filePath);
        }
        catch (XmlException) { return; /* not all files in \Tasks are valid task XML */ }

        var ns = new XmlNamespaceManager(xml.NameTable);
        ns.AddNamespace("t", "http://schemas.microsoft.com/windows/2004/02/mit/task");

        // Pull every Exec/Command + Exec/Arguments + Exec/WorkingDirectory.
        var commands = SelectAll(xml, "//t:Exec/t:Command",          ns);
        var args     = SelectAll(xml, "//t:Exec/t:Arguments",        ns);
        var workdirs = SelectAll(xml, "//t:Exec/t:WorkingDirectory", ns);
        // Author / URI hint at malware sometimes too.
        var author   = SelectFirst(xml, "//t:RegistrationInfo/t:Author", ns);
        var uri      = SelectFirst(xml, "//t:RegistrationInfo/t:URI",    ns);

        if (commands.Count == 0 && args.Count == 0)
            return; // event-only or COM-handler-only task; nothing to match.

        var matchTargets = new List<string> { relName };
        matchTargets.AddRange(commands);
        matchTargets.AddRange(args);
        matchTargets.AddRange(workdirs);
        if (author != null) matchTargets.Add(author);
        if (uri    != null) matchTargets.Add(uri);

        var matched = matchTargets
            .SelectMany(t => KnownCheats.MatchKeywords(t, KnownCheats.NameKeywords))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        bool runsJar = commands.Concat(args).Any(c =>
            c.Contains(".jar", StringComparison.OrdinalIgnoreCase) ||
            c.Contains("javaw", StringComparison.OrdinalIgnoreCase));

        bool runsFromTemp = commands.Concat(args).Concat(workdirs).Any(c =>
            c.Contains("\\temp\\", StringComparison.OrdinalIgnoreCase) ||
            c.Contains("\\downloads\\", StringComparison.OrdinalIgnoreCase) ||
            c.Contains("\\appdata\\local\\temp\\", StringComparison.OrdinalIgnoreCase));

        string detail = $"task={relName}\ncommand={string.Join(" | ", commands)}\nargs={string.Join(" | ", args)}";

        if (matched.Count > 0)
        {
            hits++;
            ConsoleUI.Hit($"  task '{relName}' matches cheat keyword(s) [{string.Join(",", matched)}]");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Hit,
                Title: $"Scheduled task matches cheat keyword: {relName}",
                Detail: detail + $"\nmatched: {string.Join(", ", matched)}",
                FilePath: filePath,
                Tags: matched.Concat(new[] { "scheduled-task" }).ToArray()));
        }
        else if (runsJar || runsFromTemp)
        {
            ConsoleUI.Warn($"  task '{relName}' is unusual ({(runsJar ? "runs jar" : "runs from temp")})");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Warn,
                Title: $"Unusual scheduled task: {relName}",
                Detail: detail,
                FilePath: filePath,
                Tags: new[] { "scheduled-task", runsJar ? "runs-jar" : "runs-from-temp" }));
        }
    }

    private static List<string> SelectAll(XmlDocument doc, string xpath, XmlNamespaceManager ns)
    {
        var list = new List<string>();
        var nodes = doc.SelectNodes(xpath, ns);
        if (nodes == null) return list;
        foreach (XmlNode n in nodes)
            if (!string.IsNullOrWhiteSpace(n.InnerText))
                list.Add(n.InnerText);
        return list;
    }

    private static string? SelectFirst(XmlDocument doc, string xpath, XmlNamespaceManager ns)
    {
        var node = doc.SelectSingleNode(xpath, ns);
        return string.IsNullOrWhiteSpace(node?.InnerText) ? null : node.InnerText;
    }
}
