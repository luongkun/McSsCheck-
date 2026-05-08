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
        "celestial", "swag", "swagclient", "swagware", "ravenb",
        "alpine-client", "alpineclient", "exelium", "exhibition",
        "hyperium", "expensive", "expensive-client", "redaktor",
        "miawh", "miawhclient", "atomic", "atomic-client",
        "polar-client", "polarclient", "rich-client", "richclient",
        "snk", "snake-client", "snakeware", "vector", "vectorclient",
        "azura", "azura-client", "trolling", "trollware",
        "konami", "kazumi", "infinitehack", "drowned", "drowned-client",
        "negativity", "haiku", "moho-client", "moho",

        // Paid / closed clients
        "vape", "vapelite", "vapev4", "remmy", "lambda",
        "impact-client", "impact ", "drip-client", "rise-client",
        "hyper-client", "hyperclient", "exo-client", "exoclient",
        "blossom-client", "blossomclient", "valyrian", "yes-client",
        "yesclient", "redaktor-client", "lithium-cheat", "nextgen",
        "next-gen", "mer-client", "merclient",

        // Generic suspicious markers
        "client.jar", "cheat", "ghostclient", "x-ray", "xray",
        "freecam", "killaura", "scaffold", "criticals", "reach-mod",
        "fakelag", "no-knockback", "noknockback", "antiknockback",
        "auto-clicker", "autoclicker", "auto-totem", "autototem",
        "auto-soup", "autosoup", "speedmine", "fastplace", "fastbreak",
        "anti-bot", "antibot", "pvp-cheat", "pvpcheat", "ghostware",
        "haxware", "hax-client", "haxclient",

        // Java agent / injection helpers commonly used by cheats
        "javaagent", "agent.jar", "injector", "hacked-client",
        "loader-1", "ldr-loader", "boot-loader.jar", "bootstrap-",
        "transformer-cheat", "weave-loader", "weave-mod", "weaveloader",
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
        "autoclicker", "autototem", "antifire", "antibot",
        "fakelag", "fakeplayer", "regen", "velocity-bypass",
        "noslow", "nofall", "auto-respawn", "playeresp",
        "chestesp", "itemesp", "wallhack", "trichat",
        "module/movement/", "module/combat/", "module/render/",
        "modules/killaura", "modules/scaffold", "modules/reach",
    };

    /// <summary>
    /// Process executable names commonly seen for *external* cheats — i.e.
    /// loaders that inject into javaw.exe instead of being a self-contained
    /// jar (Vape v4, Doomsday external, Sigma external, etc.). Matches
    /// substring on Process.Name (no extension).
    /// </summary>
    public static readonly string[] ExternalCheatProcessNames =
    {
        "vape",        "vapev4",      "vape-v4",   "vapelite",
        "doomsday",    "doomsdayloader",
        "sigma",       "sigmaloader", "sigmaclient",
        "future",      "futureloader",
        "novoline",    "novolineloader",
        "nextgen",     "nextgenloader",
        "rise",        "riseloader",
        "exo",         "exoloader",
        "hyperium",    "hyperiumloader",
        "lambda",      "lambdaloader",
        "celestial",   "celestialloader",
        "polar",       "polarloader",
        "killauraloader", "scaffoldloader",
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
