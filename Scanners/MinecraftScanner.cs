using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.Versioning;
using McSsCheck.Data;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

[SupportedOSPlatform("windows")]
internal static class MinecraftScanner
{
    public static void Run()
    {
        ConsoleUI.Section("Minecraft installations and mods");

        var roots = FindMinecraftRoots().ToList();
        if (roots.Count == 0)
        {
            ConsoleUI.Ok("No .minecraft folder found in standard locations.");
            return;
        }

        foreach (var root in roots)
        {
            ConsoleUI.Info($"Found Minecraft folder: {root}");
            ScanMods(Path.Combine(root, "mods"));
            ScanLibrariesAndVersions(root);
            ScanLauncherProfiles(root);
            ScanResourcePacks(Path.Combine(root, "resourcepacks"));
        }
    }

    private static IEnumerable<string> FindMinecraftRoots()
    {
        // Vanilla / stock launcher locations
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var localAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        var candidates = new[]
        {
            Path.Combine(appdata, ".minecraft"),
            Path.Combine(profile, ".minecraft"),
            Path.Combine(profile, "AppData", "Roaming", ".minecraft"),
            // Lunar / Badlion / PolyMC / Prism / MultiMC / TLauncher spots
            Path.Combine(localAppdata, "Programs", "lunarclient", "natives"),
            Path.Combine(profile, ".lunarclient"),
            Path.Combine(profile, "AppData", "Roaming", ".lunarclient"),
            Path.Combine(profile, "AppData", "Roaming", ".technic"),
            Path.Combine(profile, "AppData", "Roaming", ".feather"),
            Path.Combine(profile, "AppData", "Roaming", ".tlauncher"),
            Path.Combine(localAppdata, "Programs", "PrismLauncher"),
            Path.Combine(profile, "scoop", "apps", "prismlauncher"),
        };

        foreach (var c in candidates)
        {
            if (!string.IsNullOrEmpty(c) && Directory.Exists(c))
                yield return c;
        }
    }

    private static void ScanMods(string modsDir)
    {
        if (!Directory.Exists(modsDir))
        {
            ConsoleUI.Dim($"  no mods folder: {modsDir}");
            return;
        }

        var jars = Directory.EnumerateFiles(modsDir, "*.jar", SearchOption.AllDirectories).ToList();
        ConsoleUI.Info($"  mods/ contains {jars.Count} jar(s)");

        foreach (var jar in jars)
        {
            InspectJar(jar);
        }
    }

    private static void ScanLibrariesAndVersions(string mcRoot)
    {
        // versions/<id>/<id>.jar — known cheat names sometimes hide here.
        var versionsDir = Path.Combine(mcRoot, "versions");
        if (!Directory.Exists(versionsDir)) return;

        foreach (var dir in Directory.EnumerateDirectories(versionsDir))
        {
            var dirName = Path.GetFileName(dir);
            var hits = KnownCheats.MatchKeywords(dirName, KnownCheats.NameKeywords).ToList();
            if (hits.Count > 0)
                ConsoleUI.Hit($"  versions/{dirName} matches cheat keyword(s) [{string.Join(",", hits)}]");

            foreach (var jar in Directory.EnumerateFiles(dir, "*.jar", SearchOption.TopDirectoryOnly))
                InspectJar(jar);
        }
    }

    private static void ScanLauncherProfiles(string mcRoot)
    {
        var profilesPath = Path.Combine(mcRoot, "launcher_profiles.json");
        if (!File.Exists(profilesPath)) return;

        try
        {
            var content = File.ReadAllText(profilesPath);
            foreach (var kw in KnownCheats.MatchKeywords(content, KnownCheats.NameKeywords))
                ConsoleUI.Hit($"  launcher_profiles.json mentions cheat keyword: {kw}");
        }
        catch (Exception ex)
        {
            ConsoleUI.Dim($"  cannot read launcher_profiles.json: {ex.Message}");
        }
    }

    private static void ScanResourcePacks(string rpDir)
    {
        if (!Directory.Exists(rpDir)) return;

        foreach (var entry in Directory.EnumerateFileSystemEntries(rpDir))
        {
            var name = Path.GetFileName(entry);
            // X-ray resource packs are extremely common cheat aids.
            if (name.Contains("xray", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("x-ray", StringComparison.OrdinalIgnoreCase) ||
                name.Contains("ore-finder", StringComparison.OrdinalIgnoreCase))
            {
                ConsoleUI.Hit($"  suspicious resourcepack: {entry}");
            }
        }
    }

    private static void InspectJar(string jarPath)
    {
        var fileName = Path.GetFileName(jarPath);
        var nameHits = KnownCheats.MatchKeywords(fileName, KnownCheats.NameKeywords).ToList();
        if (nameHits.Count > 0)
        {
            ConsoleUI.Hit($"  jar name matches cheat keyword(s) [{string.Join(",", nameHits)}]: {jarPath}");
        }

        FileInfo fi;
        try { fi = new FileInfo(jarPath); }
        catch { return; }

        try
        {
            var sha = HashUtil.Sha256OfFile(jarPath);
            ConsoleUI.Dim($"    {fileName}  size={fi.Length}  sha256={sha}  mtime={fi.LastWriteTime:yyyy-MM-dd HH:mm}");
        }
        catch (Exception ex)
        {
            ConsoleUI.Dim($"    {fileName}  (hash failed: {ex.Message})");
        }

        // Inspect entry names inside the jar
        try
        {
            using var zip = ZipFile.OpenRead(jarPath);
            foreach (var entry in zip.Entries)
            {
                var entryName = entry.FullName;
                var hits = KnownCheats.MatchKeywords(entryName, KnownCheats.InternalKeywords).ToList();
                if (hits.Count > 0)
                {
                    ConsoleUI.Hit($"    internal entry hits [{string.Join(",", hits)}]: {entryName}");
                    continue;
                }

                var nameHits2 = KnownCheats.MatchKeywords(entryName, KnownCheats.NameKeywords).ToList();
                if (nameHits2.Count > 0)
                    ConsoleUI.Hit($"    internal entry hits [{string.Join(",", nameHits2)}]: {entryName}");
            }
        }
        catch (Exception ex)
        {
            ConsoleUI.Dim($"    (cannot open jar: {ex.Message})");
        }
    }
}
