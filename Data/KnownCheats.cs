using System;
using System.Collections.Generic;

namespace McSsCheck.Data;

/// <summary>
/// Public, well-known Minecraft Java cheat-client / utility-mod names.
/// Matching is intentionally substring-based and case-insensitive: it flags
/// likely candidates for manual review, not "guilty" verdicts.
/// </summary>
internal static class KnownCheats
{
    /// <summary>
    /// Substrings to look for in jar filenames, jar internal entries,
    /// MANIFEST main-class names, prefetch entries, etc.
    /// </summary>
    public static readonly string[] NameKeywords =
    {
        // Free / open-source clients
        "wurst", "meteor", "liquidbounce", "rusherhack", "hexware",
        "aristois", "doomsday", "future", "salhack", "konas", "wolfram",
        "huzuni", "nodus", "kami", "loliware", "bleachhack", "cosmos",
        "skillclient", "raven", "fenix", "flux", "pyro", "astro",
        "tenacity", "inertia", "matrix-client", "gateclient", "sigma",
        "novoline", "ares", "phobos", "moon-client", "moonclient",

        // Paid / closed clients
        "vape", "vapelite", "vapev4", "remmy", "lambda",
        "impact-client", "impact ", "drip-client", "rise-client",

        // Generic suspicious markers
        "client.jar", "cheat", "ghostclient", "x-ray", "xray",
        "freecam", "killaura", "scaffold", "criticals", "reach-mod",

        // Java agent / injection helpers commonly used by cheats
        "javaagent", "agent.jar", "injector", "hacked-client",
    };

    /// <summary>
    /// Domains commonly visited when downloading Minecraft cheats.
    /// </summary>
    public static readonly string[] CheatDomains =
    {
        "wurstclient.net",
        "meteorclient.com",
        "liquidbounce.net",
        "impactclient.net",
        "aristois.net",
        "rusherhack.org",
        "doomsday.gg",
        "future.eu",
        "vape.gg",
        "sigmaclient.net",
        "sigmaclient.io",
        "novoline.cc",
        "rise.ware",
        "moonclient.io",
        "ghostclient.net",
        "pyroclient.com",
        "salhack.net",
        "lambdaclient.io",
        "bleachhack.org",
    };

    /// <summary>
    /// Folder name fragments that often appear inside packed cheats / loaders.
    /// </summary>
    public static readonly string[] InternalKeywords =
    {
        "killaura", "scaffold", "reach", "tracer", "freecam",
        "antiknockback", "noslowdown", "fastbreak", "fastplace",
        "criticals", "step", "phase", "flight", "speedhack",
        "xray", "esp", "aimassist",
    };

    public static IEnumerable<string> MatchKeywords(string haystack, IEnumerable<string> keywords)
    {
        if (string.IsNullOrEmpty(haystack)) yield break;
        foreach (var kw in keywords)
        {
            if (haystack.Contains(kw, StringComparison.OrdinalIgnoreCase))
                yield return kw;
        }
    }
}
