using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.Versioning;
using McSsCheck.Data;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

[SupportedOSPlatform("windows")]
internal static class MinecraftScanner
{
    public const string SourceName = "MinecraftScanner";

    /// <summary>Maps every hashed jar path to its (sha256, size) for downstream VT lookup.</summary>
    public static Dictionary<string, (string Sha256, long Size)> JarHashes { get; } =
        new(StringComparer.OrdinalIgnoreCase);

    public static void Run(SessionReport report, SessionReport.Section section)
    {
        ConsoleUI.Section("Minecraft installations and mods");
        JarHashes.Clear();
        report.Mods.Clear();

        var roots = FindMinecraftRoots().ToList();
        if (roots.Count == 0)
        {
            ConsoleUI.Ok("No .minecraft folder found in standard locations.");
            return;
        }

        foreach (var root in roots)
        {
            ConsoleUI.Info($"Found Minecraft folder: {root}");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Info,
                Title: "Minecraft folder found", Detail: root, FilePath: root));

            ScanMods(Path.Combine(root, "mods"), report, section);
            ScanLibrariesAndVersions(root, report, section);
            ScanLauncherProfiles(root, section);
            ScanResourcePacks(Path.Combine(root, "resourcepacks"), section);
        }
    }

    private static IEnumerable<string> FindMinecraftRoots()
    {
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var candidates = new[]
        {
            Path.Combine(appdata, ".minecraft"),
            Path.Combine(profile, ".minecraft"),
            Path.Combine(profile, "AppData", "Roaming", ".minecraft"),
            Path.Combine(localAppdata, "Programs", "lunarclient", "natives"),
            Path.Combine(profile, ".lunarclient"),
            Path.Combine(profile, "AppData", "Roaming", ".lunarclient"),
            Path.Combine(profile, "AppData", "Roaming", ".technic"),
            Path.Combine(profile, "AppData", "Roaming", ".feather"),
            Path.Combine(profile, "AppData", "Roaming", ".tlauncher"),
            Path.Combine(localAppdata, "Programs", "PrismLauncher"),
            Path.Combine(profile, "scoop", "apps", "prismlauncher"),
        };

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in candidates)
        {
            if (string.IsNullOrEmpty(c) || !Directory.Exists(c)) continue;
            if (seen.Add(c)) yield return c;
        }
    }

    private static void ScanMods(string modsDir, SessionReport report, SessionReport.Section section)
    {
        if (!Directory.Exists(modsDir))
        {
            ConsoleUI.Dim($"  no mods folder: {modsDir}");
            return;
        }

        var jars = Directory.EnumerateFiles(modsDir, "*.jar", SearchOption.AllDirectories).ToList();
        ConsoleUI.Info($"  mods/ contains {jars.Count} jar(s)");

        foreach (var jar in jars) InspectJar(jar, report, section);
    }

    private static void ScanLibrariesAndVersions(string mcRoot, SessionReport report, SessionReport.Section section)
    {
        var versionsDir = Path.Combine(mcRoot, "versions");
        if (!Directory.Exists(versionsDir)) return;

        foreach (var dir in Directory.EnumerateDirectories(versionsDir))
        {
            var dirName = Path.GetFileName(dir);
            var hits = KnownCheats.MatchKeywords(dirName, KnownCheats.NameKeywords).ToList();
            if (hits.Count > 0)
            {
                ConsoleUI.Hit($"  versions/{dirName} matches cheat keyword(s) [{string.Join(",", hits)}]");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Hit,
                    Title: "versions/ folder matches cheat keyword",
                    Detail: $"folder name '{dirName}' matched: {string.Join(", ", hits)}",
                    FilePath: dir, Tags: hits.ToArray()));
            }

            foreach (var jar in Directory.EnumerateFiles(dir, "*.jar", SearchOption.TopDirectoryOnly))
                InspectJar(jar, report, section);
        }
    }

    private static void ScanLauncherProfiles(string mcRoot, SessionReport.Section section)
    {
        var profilesPath = Path.Combine(mcRoot, "launcher_profiles.json");
        if (!File.Exists(profilesPath)) return;

        try
        {
            var content = File.ReadAllText(profilesPath);
            foreach (var kw in KnownCheats.MatchKeywords(content, KnownCheats.NameKeywords))
            {
                ConsoleUI.Hit($"  launcher_profiles.json mentions cheat keyword: {kw}");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Hit,
                    Title: "launcher_profiles.json mentions cheat keyword",
                    Detail: $"keyword: {kw}",
                    FilePath: profilesPath, Tags: new[] { kw }));
            }
        }
        catch (Exception ex)
        {
            ConsoleUI.Dim($"  cannot read launcher_profiles.json: {ex.Message}");
        }
    }

    private static void ScanResourcePacks(string rpDir, SessionReport.Section section)
    {
        if (!Directory.Exists(rpDir)) return;

        foreach (var entry in Directory.EnumerateFileSystemEntries(rpDir))
        {
            var name = Path.GetFileName(entry);
            if (name.Contains("xray", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("x-ray", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("ore-finder", StringComparison.OrdinalIgnoreCase))
            {
                ConsoleUI.Hit($"  suspicious resourcepack: {entry}");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Hit,
                    Title: "Suspicious resourcepack",
                    Detail: name, FilePath: entry,
                    Tags: new[] { "xray-pack" }));
            }
        }
    }

    private static void InspectJar(string jarPath, SessionReport report, SessionReport.Section section)
    {
        var fileName = Path.GetFileName(jarPath);
        var nameHits = KnownCheats.MatchKeywords(fileName, KnownCheats.NameKeywords).ToList();
        if (nameHits.Count > 0)
        {
            ConsoleUI.Hit($"  jar name matches cheat keyword(s) [{string.Join(",", nameHits)}]: {jarPath}");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Hit,
                Title: "Jar filename matches cheat keyword",
                Detail: string.Join(", ", nameHits),
                FilePath: jarPath, Tags: nameHits.ToArray()));
        }

        FileInfo fi;
        try { fi = new FileInfo(jarPath); }
        catch { return; }

        string? sha = null;
        string? sha1 = null;
        try
        {
            (sha, sha1) = HashUtil.Sha256AndSha1OfFile(jarPath);
            JarHashes[jarPath] = (sha, fi.Length);
            ConsoleUI.Dim($"    {fileName}  size={fi.Length}  sha1={sha1}  sha256={sha}  mtime={fi.LastWriteTime:yyyy-MM-dd HH:mm}");
        }
        catch (Exception ex)
        {
            ConsoleUI.Dim($"    {fileName}  (hash failed: {ex.Message})");
        }

        report.Mods.Add(new ModEntry
        {
            FileName = fileName,
            FilePath = jarPath,
            Size     = fi.Length,
            Modified = fi.LastWriteTime,
            Sha1     = sha1,
            Sha256   = sha,
        });

        try
        {
            using var zip = ZipFile.OpenRead(jarPath);
            int totalClass = 0, shortName = 0;
            double totalEntropy = 0;
            int sampledClasses = 0;
            bool hasProGuard = false, hasAllatori = false, hasObfuscatorMarker = false;

            foreach (var entry in zip.Entries)
            {
                var entryName = entry.FullName;

                var hits = KnownCheats.MatchKeywords(entryName, KnownCheats.InternalKeywords).ToList();
                if (hits.Count > 0)
                {
                    ConsoleUI.Hit($"    internal entry hits [{string.Join(",", hits)}]: {entryName}");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Hit,
                        Title: "Suspicious entry inside jar",
                        Detail: $"entry '{entryName}' matched: {string.Join(", ", hits)}",
                        FilePath: jarPath, Hash: sha,
                        Tags: hits.ToArray()));
                }

                var nameHits2 = KnownCheats.MatchKeywords(entryName, KnownCheats.NameKeywords).ToList();
                if (nameHits2.Count > 0)
                {
                    ConsoleUI.Hit($"    internal entry hits [{string.Join(",", nameHits2)}]: {entryName}");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Hit,
                        Title: "Cheat-named entry inside jar",
                        Detail: $"entry '{entryName}' matched: {string.Join(", ", nameHits2)}",
                        FilePath: jarPath, Hash: sha,
                        Tags: nameHits2.ToArray()));
                }

                if (entryName.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
                {
                    totalClass++;
                    var classFile = Path.GetFileNameWithoutExtension(entryName);
                    if (classFile.Length <= 2) shortName++;

                    if (sampledClasses < 32)
                    {
                        try
                        {
                            using var es = entry.Open();
                            totalEntropy += EntropyUtil.ShannonStream(es, 65536);
                            sampledClasses++;
                        }
                        catch { /* ignore */ }
                    }
                }

                var lower = entryName.ToLowerInvariant();
                if (lower.Contains("proguard")) hasProGuard = true;
                if (lower.Contains("allatori")) hasAllatori = true;
                if (lower.EndsWith(".class.encrypted") || lower.Contains("/stringer/") || lower.Contains("/zelix/"))
                    hasObfuscatorMarker = true;
            }

            if (totalClass > 0)
            {
                double shortRatio = (double)shortName / totalClass;
                double avgEntropy = sampledClasses > 0 ? totalEntropy / sampledClasses : 0;
                bool packed = false;
                var reasons = new List<string>();

                if (shortRatio > 0.40 && totalClass >= 10)
                { packed = true; reasons.Add($"obfuscated names ({shortName}/{totalClass} short)"); }

                if (avgEntropy > 7.6 && sampledClasses > 0)
                { packed = true; reasons.Add($"high class entropy ({avgEntropy:F2}/8)"); }

                if (hasProGuard)         { packed = true; reasons.Add("ProGuard markers"); }
                if (hasAllatori)         { packed = true; reasons.Add("Allatori markers"); }
                if (hasObfuscatorMarker) { packed = true; reasons.Add("Stringer/Zelix markers"); }

                if (packed)
                {
                    var reason = string.Join("; ", reasons);
                    ConsoleUI.Hit($"    jar appears packed/obfuscated: {fileName}  reasons: {reason}");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Hit,
                        Title: "Jar appears packed/obfuscated",
                        Detail: reason,
                        FilePath: jarPath, Hash: sha,
                        Tags: new[] { "packed-jar" }));
                }
            }
        }
        catch (Exception ex)
        {
            ConsoleUI.Dim($"    (cannot open jar: {ex.Message})");
        }
    }
}
