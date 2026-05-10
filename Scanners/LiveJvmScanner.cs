using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Management;
using System.Runtime.Versioning;
using McSsCheck.Data;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

/// <summary>
/// Inspects every running <c>javaw.exe</c> / <c>java.exe</c> process and uses
/// its <c>-cp</c> / <c>-classpath</c> to enumerate the jars Minecraft is
/// actually loading right now. Each matched jar is added to <c>report.Mods</c>
/// (so it shows up in the Modrinth verification table) and a HIT for any cheat
/// keyword on a *currently loaded* jar is tagged with <c>active</c>, so the
/// HTML report renders it as a red "Boot instance" pill.
///
/// Also flags orphan jars in <c>mods/</c> that are NOT on the classpath
/// (a player could hide a jar by removing it from the active mod set without
/// deleting it).
/// </summary>
[SupportedOSPlatform("windows")]
internal static class LiveJvmScanner
{
    public const string SourceName = "LiveJvmScanner";

    public static void Run(SessionReport report, SessionReport.Section section)
    {
        ConsoleUI.Section("Live JVM scan (jars currently loaded by Minecraft)");

        var jvms = QueryJvms(section).ToList();
        if (jvms.Count == 0)
        {
            ConsoleUI.Ok("No java.exe / javaw.exe processes are currently running — skipping live scan.");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Info,
                Title: "No live JVM",
                Detail: "Minecraft is not running, so the live classpath cannot be inspected. The disk-based MinecraftScanner still scans the .minecraft folder."));
            return;
        }

        // Track jar paths the JVM has on its classpath, so we can spot orphans
        // (jar in mods/ but NOT on classpath).
        var loadedPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var p in jvms)
        {
            ConsoleUI.Info($"PID {p.Pid} {p.Name} cmdline len={p.CommandLine?.Length ?? 0}");

            string? mainClass = ExtractMainClass(p.CommandLine);
            string? loader    = DetectModLoader(mainClass, p.CommandLine);
            if (loader != null)
            {
                ConsoleUI.Info($"  mod loader: {loader} (main class: {mainClass ?? "?"})");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Info,
                    Title: $"Mod loader detected: {loader}",
                    Detail: $"PID {p.Pid} main class = {mainClass ?? "?"}",
                    Tags: new[] { "loader", loader.ToLowerInvariant() }));
            }

            var classpath = ExtractClasspath(p.CommandLine);
            if (classpath.Count == 0)
            {
                ConsoleUI.Dim("  no -cp / -classpath in cmdline (jvm might be early-bootstrap or wrapped)");
                continue;
            }

            ConsoleUI.Info($"  classpath has {classpath.Count} jar(s) on it");

            foreach (var jar in classpath)
            {
                if (string.IsNullOrEmpty(jar)) continue;
                loadedPaths.Add(jar);
                InspectLoadedJar(jar, p.Pid, loader, report, section);
            }
        }

        // After all live JVMs scanned, look for jars in mods/ that are NOT on
        // any classpath -> orphans (player took them out of active set).
        ScanOrphanMods(loadedPaths, section);
    }

    // ----------------------------------------------------------------------

    private record JvmEntry(int Pid, string Name, string? CommandLine);

    private static IEnumerable<JvmEntry> QueryJvms(SessionReport.Section section)
    {
        const string query = "SELECT ProcessId, Name, CommandLine FROM Win32_Process " +
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
                Title: "WMI query failed", Detail: ex.Message));
            yield break;
        }
        foreach (ManagementObject mo in results)
        {
            int pid = Convert.ToInt32(mo["ProcessId"]);
            var n = mo["Name"] as string ?? "";
            var c = mo["CommandLine"] as string;
            yield return new JvmEntry(pid, n, c);
        }
    }

    private static List<string> ExtractClasspath(string? cmd)
    {
        var jars = new List<string>();
        if (string.IsNullOrEmpty(cmd)) return jars;
        var tokens = CmdlineTokenizer.Tokenize(cmd).ToList();
        for (int i = 0; i < tokens.Count - 1; i++)
        {
            if (tokens[i].Equals("-cp", StringComparison.OrdinalIgnoreCase) ||
                tokens[i].Equals("-classpath", StringComparison.OrdinalIgnoreCase))
            {
                var raw = tokens[i + 1];
                foreach (var p in raw.Split(';', StringSplitOptions.RemoveEmptyEntries))
                    jars.Add(p.Trim());
                break;
            }
        }
        return jars;
    }

    private static string? ExtractMainClass(string? cmd)
    {
        if (string.IsNullOrEmpty(cmd)) return null;
        var toks = CmdlineTokenizer.Tokenize(cmd).ToList();
        // Main class is the first non-flag token after -cp / -jar / a final standalone arg.
        for (int i = 0; i < toks.Count; i++)
        {
            if (toks[i].Equals("-cp", StringComparison.OrdinalIgnoreCase) ||
                toks[i].Equals("-classpath", StringComparison.OrdinalIgnoreCase))
            {
                if (i + 2 < toks.Count) return toks[i + 2];
            }
        }
        // Fallback: scan for a token that looks like a fully-qualified class name.
        for (int i = toks.Count - 1; i >= 0; i--)
        {
            var t = toks[i];
            if (t.StartsWith("-")) continue;
            if (t.Contains('.') && !t.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
                return t;
        }
        return null;
    }

    private static string? DetectModLoader(string? mainClass, string? cmd)
    {
        var blob = ((mainClass ?? "") + " " + (cmd ?? "")).ToLowerInvariant();
        if (blob.Contains("net.fabricmc.loader") || blob.Contains("knotclient") || blob.Contains("knotserver"))
            return "Fabric";
        if (blob.Contains("net.minecraftforge.bootstrap") || blob.Contains("cpw.mods.modlauncher")
            || blob.Contains("forgewrapper"))
            return "Forge";
        if (blob.Contains("net.neoforged"))
            return "NeoForge";
        if (blob.Contains("org.quiltmc.loader"))
            return "Quilt";
        if (blob.Contains("net.minecraft.client.main.main"))
            return "Vanilla";
        if (blob.Contains("com.moonsworth.lunar"))
            return "Lunar Client";
        if (blob.Contains("net.feathermc"))
            return "Feather Client";
        if (blob.Contains("net.badlion"))
            return "Badlion Client";
        return null;
    }

    private static void InspectLoadedJar(string jarPath, int pid, string? loader,
                                          SessionReport report, SessionReport.Section section)
    {
        if (!File.Exists(jarPath))
        {
            // Could be a directory entry (`bin/` etc.) or a missing file.
            ConsoleUI.Dim($"    classpath entry not a file: {jarPath}");
            return;
        }

        var fileName = Path.GetFileName(jarPath);
        var nameHits = KnownCheats.MatchKeywords(fileName, KnownCheats.NameKeywords).ToList();

        FileInfo fi;
        try { fi = new FileInfo(jarPath); }
        catch (Exception ex)
        {
            ConsoleUI.Dim($"    cannot stat: {jarPath}: {ex.Message}");
            return;
        }

        string? sha256 = null;
        string? sha1   = null;
        try
        {
            (sha256, sha1) = HashUtil.Sha256AndSha1OfFile(jarPath);
        }
        catch (Exception ex)
        {
            ConsoleUI.Dim($"    hash failed for {jarPath}: {ex.Message}");
        }

        // Add (or upsert) into report.Mods so Modrinth + the Mods Logs table
        // include this loaded jar.
        var existing = report.Mods.FirstOrDefault(m => string.Equals(m.FilePath, jarPath, StringComparison.OrdinalIgnoreCase));
        if (existing == null)
        {
            report.Mods.Add(new ModEntry
            {
                FileName = fileName,
                FilePath = jarPath,
                Size     = fi.Length,
                Modified = fi.LastWriteTime,
                Sha1     = sha1,
                Sha256   = sha256,
                Notes    = $"loaded by PID {pid}" + (loader != null ? $" ({loader})" : ""),
            });
        }
        else if (existing.Notes == null)
        {
            existing.Notes = $"loaded by PID {pid}" + (loader != null ? $" ({loader})" : "");
        }

        if (nameHits.Count > 0)
        {
            var tag = new List<string>(nameHits) { "active", "loaded-jar" };
            ConsoleUI.Hit($"    LOADED jar matches cheat keyword(s) [{string.Join(",", nameHits)}]: {jarPath}");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Hit,
                Title: "LOADED jar matches cheat keyword (live JVM)",
                Detail: $"PID {pid} loaded jar '{fileName}' matched: {string.Join(", ", nameHits)}",
                FilePath: jarPath, Hash: sha256,
                Tags: tag.ToArray()));
        }

        // Inspect jar contents for cheat-internal markers.
        try
        {
            using var zip = ZipFile.OpenRead(jarPath);
            int totalClass = 0, shortName = 0;
            foreach (var entry in zip.Entries)
            {
                var entryName = entry.FullName;
                var iHits = KnownCheats.MatchKeywords(entryName, KnownCheats.InternalKeywords).ToList();
                if (iHits.Count > 0)
                {
                    var tag = new List<string>(iHits) { "active", "internal-class" };
                    ConsoleUI.Hit($"    LOADED jar internal entry hits [{string.Join(",", iHits)}]: {entryName}");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Hit,
                        Title: "LOADED jar contains cheat-internal entry",
                        Detail: $"jar '{fileName}' entry '{entryName}' matched: {string.Join(", ", iHits)}",
                        FilePath: jarPath, Hash: sha256,
                        Tags: tag.ToArray()));
                }
                if (entryName.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                {
                    totalClass++;
                    if (Path.GetFileNameWithoutExtension(entryName).Length <= 2) shortName++;
                }
            }

            if (totalClass >= 10 && (double)shortName / totalClass > 0.40)
            {
                ConsoleUI.Hit($"    LOADED jar appears packed/obfuscated: {fileName}");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Hit,
                    Title: "LOADED jar appears packed/obfuscated (live JVM)",
                    Detail: $"jar '{fileName}' has {shortName}/{totalClass} short class names",
                    FilePath: jarPath, Hash: sha256,
                    Tags: new[] { "packed-jar", "active" }));
            }
        }
        catch (Exception ex)
        {
            ConsoleUI.Dim($"    cannot open loaded jar: {ex.Message}");
        }
    }

    private static void ScanOrphanMods(HashSet<string> loadedPaths, SessionReport.Section section)
    {
        var modsRoots = new List<string>();
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (var root in new[]
        {
            Path.Combine(appdata, ".minecraft", "mods"),
            Path.Combine(profile, ".minecraft", "mods"),
            Path.Combine(profile, ".lunarclient", "mods"),
            Path.Combine(appdata, ".feather", "mods"),
            Path.Combine(appdata, ".tlauncher", "mods"),
        })
        {
            if (Directory.Exists(root)) modsRoots.Add(root);
        }

        foreach (var modsDir in modsRoots)
        {
            try
            {
                var jars = Directory.EnumerateFiles(modsDir, "*.jar", SearchOption.AllDirectories);
                foreach (var jar in jars)
                {
                    if (loadedPaths.Contains(jar)) continue;

                    var name = Path.GetFileName(jar);
                    var lower = name.ToLowerInvariant();
                    // Disabled mods (.jar.disabled) are intentionally excluded by the
                    // launcher; not an orphan, just skipped by the player.
                    if (lower.EndsWith(".jar.disabled")) continue;

                    var hits = KnownCheats.MatchKeywords(name, KnownCheats.NameKeywords).ToList();
                    var sev  = hits.Count > 0 ? Severity.Hit : Severity.Warn;
                    var tags = new List<string>(hits) { "orphan-mod" };
                    ConsoleUI.Warn($"  orphan jar in {modsDir}: {name}{(hits.Count > 0 ? "  matched=[" + string.Join(",", hits) + "]" : "")}");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: sev,
                        Title: hits.Count > 0
                            ? "Orphan mod jar matches cheat keyword (not loaded by current JVM)"
                            : "Orphan mod jar (not loaded by current JVM)",
                        Detail: $"jar present in mods/ but not on the running JVM classpath: {name}",
                        FilePath: jar,
                        Tags: tags.ToArray()));
                }
            }
            catch (Exception ex)
            {
                ConsoleUI.Dim($"  cannot enumerate {modsDir}: {ex.Message}");
            }
        }
    }
}
