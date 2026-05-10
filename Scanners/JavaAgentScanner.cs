using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using McSsCheck.Data;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

/// <summary>
/// Flags every .jar whose MANIFEST.MF declares a Java instrumentation agent
/// (<c>Premain-Class</c> / <c>Agent-Class</c>) — a very strong signal for
/// cheat clients of the "javaagent" family (Doomsday, Weave, Konas-style
/// loaders, rebuilt Atermys jars, …).
///
/// Why this catches renamed / repacked cheats that every other scanner
/// misses: legitimate Minecraft mods DO NOT use <c>java.lang.instrument</c>.
/// Fabric / Forge / NeoForge / Quilt / vanilla all load mods through their
/// own loader classpath, not the JVM-level agent mechanism. So a "real"
/// mod has no <c>Premain-Class</c>. Repacking the jar or renaming the file
/// does nothing — the manifest still gives the cheat away.
///
/// We scan:
///   * every .jar under <c>.minecraft/mods/</c> + <c>versions/*/</c>
///     (covered by the disk walk MinecraftScanner already does);
///   * every .jar in the player-controlled folders (Desktop, Downloads,
///     Documents, Public, AppData, LocalAppData, %TEMP%, profile root) —
///     shared with <see cref="CheatExeScanner"/> via <see cref="UserFolders"/>,
///     so an <c>atermys.jar</c> hiding on the Desktop is still caught.
///
/// One finding per jar. Legitimate agents do exist in the wild
/// (byte-buddy-agent test harnesses, profiler helpers); the match is
/// always flagged as Hit but staff can use context — the jar's location,
/// its size, and whether it sits inside <c>.minecraft/</c> — to decide.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class JavaAgentScanner
{
    public const string SourceName = "JavaAgentScanner";

    /// <summary>Skip jars bigger than this (cheat agents are always tiny).</summary>
    private const long MaxJarBytes = 200L * 1024 * 1024;

    /// <summary>Sub-paths we always add on top of <see cref="UserFolders"/> so
    /// mods/ + versions/ + the profile folder are always walked, even if
    /// the user opts out of the Minecraft scanner with future flags.</summary>
    private static readonly string[] MinecraftSubPaths =
    {
        Path.Combine("AppData", "Roaming", ".minecraft", "mods"),
        Path.Combine("AppData", "Roaming", ".minecraft", "versions"),
        Path.Combine("AppData", "Roaming", ".lunarclient"),
        Path.Combine("AppData", "Roaming", ".feather", "mods"),
        Path.Combine("AppData", "Roaming", ".tlauncher", "mods"),
        Path.Combine("AppData", "Roaming", ".badlion"),
    };

    public static void Run(SessionReport.Section section)
    {
        ConsoleUI.Section("Java-agent manifest scan (Premain-Class / Agent-Class)");

        var roots = UserFolders.GetDefaultRoots();

        // Always ensure the standard .minecraft roots are present even on
        // unusual profile layouts — UserFolders already picks AppData so
        // the subpath walk below will cover them, but we also add the
        // scoop / Prism / LunarClient installs here.
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (var rel in MinecraftSubPaths)
        {
            if (string.IsNullOrEmpty(profile)) break;
            var full = Path.Combine(profile, rel);
            if (Directory.Exists(full) && !roots.Contains(full, StringComparer.OrdinalIgnoreCase))
                roots.Add(full);
        }

        if (roots.Count == 0)
        {
            ConsoleUI.Dim("  no scoped folders found");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Info,
                Title: "Java-agent scan: no scoped folders found",
                Detail: "Could not resolve any of Desktop / Downloads / Documents / Public / AppData / LocalAppData / %TEMP% / profile root.",
                Tags: new[] { "java-agent", "scan-summary" }));
            return;
        }

        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int jarsScanned = 0, agents = 0, errors = 0;
        var rootCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var root in roots)
        {
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(root, "*.jar", SearchOption.AllDirectories);
            }
            catch (Exception ex)
            {
                ConsoleUI.Dim($"  cannot enumerate {root}: {ex.Message}");
                errors++;
                continue;
            }

            int local = 0;
            foreach (var jar in files)
            {
                if (!visited.Add(jar)) continue;

                FileInfo fi;
                try { fi = new FileInfo(jar); }
                catch { continue; }
                if (fi.Length <= 0 || fi.Length > MaxJarBytes) continue;

                jarsScanned++;
                local++;

                var manifest = JarManifestInspector.Read(jar);
                if (manifest == null || !JarManifestInspector.IsJavaAgent(manifest))
                    continue;

                agents++;

                manifest.TryGetValue("Premain-Class",  out var premain);
                manifest.TryGetValue("Agent-Class",    out var agentCls);
                manifest.TryGetValue("Main-Class",     out var mainCls);
                manifest.TryGetValue("Can-Retransform-Classes", out var retr);
                manifest.TryGetValue("Can-Redefine-Classes",    out var redef);

                // Cross-reference the agent class name against the cheat
                // keyword list for a sharper report title when possible.
                var combined = $"{premain} {agentCls} {mainCls} {Path.GetFileName(jar)}";
                var matched = KnownCheats.MatchKeywords(combined, KnownCheats.NameKeywords).ToList();

                string title = matched.Count > 0
                    ? $"Java-agent jar matches cheat keyword(s) [{string.Join(", ", matched)}]: {Path.GetFileName(jar)}"
                    : $"Java-agent jar (Premain/Agent-Class declared): {Path.GetFileName(jar)}";

                var detail =
                    $"file={jar}\n" +
                    $"size={fi.Length}\n" +
                    (premain  != null ? $"Premain-Class={premain}\n"                : "") +
                    (agentCls != null ? $"Agent-Class={agentCls}\n"                  : "") +
                    (mainCls  != null ? $"Main-Class={mainCls}\n"                    : "") +
                    (retr     != null ? $"Can-Retransform-Classes={retr}\n"          : "") +
                    (redef    != null ? $"Can-Redefine-Classes={redef}\n"            : "") +
                    (matched.Count > 0 ? $"matched keywords: {string.Join(", ", matched)}\n" : "") +
                    "\nNote: legitimate Minecraft mods (Fabric/Forge/NeoForge/Quilt/vanilla) " +
                    "never declare a JVM-level Java agent. Cheat-agent families (Doomsday, Weave, " +
                    "Konas-style loaders, rebuilt Atermys, …) always do.";

                var tags = new List<string> { "java-agent", "manifest-agent" };
                tags.AddRange(matched);

                ConsoleUI.Hit($"  AGENT: {jar}"
                    + (premain  != null ? $"  Premain={premain}"  : "")
                    + (agentCls != null ? $"  Agent={agentCls}"   : ""));

                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Hit,
                    Title: title,
                    Detail: detail,
                    FilePath: jar, Timestamp: fi.LastWriteTime,
                    Tags: tags.ToArray()));
            }

            rootCounts[root] = local;
        }

        if (jarsScanned == 0)
        {
            ConsoleUI.Dim("  no .jar files in scoped folders");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Info,
                Title: "Java-agent scan: no .jar files in scoped folders",
                Detail: $"folders walked: {roots.Count}, jars scanned: 0, errors: {errors}",
                Tags: new[] { "java-agent", "scan-summary" }));
            return;
        }

        if (agents == 0)
        {
            ConsoleUI.Ok($"  no Premain/Agent-Class jars ({jarsScanned} jar(s) scanned across {rootCounts.Count} folder(s)).");
            var perRoot = string.Join("\n  ", rootCounts
                .OrderByDescending(kv => kv.Value)
                .Select(kv => $"- {kv.Key}: {kv.Value} jar(s)"));
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Ok,
                Title: $"Java-agent scan clean ({jarsScanned} jar(s))",
                Detail:
                    $"jars scanned: {jarsScanned}\n" +
                    $"agents found: 0\n" +
                    $"folders walked: {rootCounts.Count}\n" +
                    (rootCounts.Count == 0 ? "" : $"\nPer-folder:\n  {perRoot}"),
                Tags: new[] { "java-agent", "scan-summary" }));
        }
        else
        {
            ConsoleUI.Info($"  scanned {jarsScanned} jar(s); {agents} declared a Java agent.");
        }
    }
}
