using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Versioning;

namespace McSsCheck.Util;

/// <summary>
/// Common helper to enumerate the user-controlled folders that several
/// scanners want to walk (Desktop, Downloads, Documents, Public, AppData,
/// LocalAppData, %TEMP%, UserProfile). Previously duplicated in
/// <see cref="Scanners.CheatExeScanner"/> and
/// <see cref="Scanners.HeuristicEngineScanner"/>.
///
/// Returns a de-duplicated, full-path list in a stable order (so
/// per-folder accounting is comparable across runs). Missing folders are
/// silently dropped.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class UserFolders
{
    /// <summary>Desktop / Downloads / Documents / Public / AppData / LocalAppData / %TEMP% / UserProfile.</summary>
    public static List<string> GetDefaultRoots()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var docs    = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var local   = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var dl      = string.IsNullOrEmpty(profile) ? "" : Path.Combine(profile, "Downloads");
        var temp    = Path.GetTempPath();
        var pubDir  = Environment.GetEnvironmentVariable("PUBLIC") ?? @"C:\Users\Public";

        return Normalize(new[] { desktop, docs, dl, temp, pubDir, appdata, local, profile });
    }

    /// <summary>Lighter list used by ADS heuristics (no AppData/LocalAppData/Temp).</summary>
    public static List<string> GetDropFolders()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        var docs    = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
        var appdata = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var dl      = string.IsNullOrEmpty(profile) ? "" : Path.Combine(profile, "Downloads");
        var mc      = string.IsNullOrEmpty(appdata) ? "" : Path.Combine(appdata, ".minecraft");

        return Normalize(new[] { desktop, docs, dl, mc, profile });
    }

    private static List<string> Normalize(IEnumerable<string> candidates)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<string>();
        foreach (var c in candidates)
        {
            if (string.IsNullOrEmpty(c)) continue;
            string norm;
            try { norm = Path.GetFullPath(c).TrimEnd('\\'); }
            catch { continue; }
            if (!Directory.Exists(norm)) continue;
            if (seen.Add(norm)) result.Add(norm);
        }
        return result;
    }
}
