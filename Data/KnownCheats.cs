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

        // Newer / less-known clients & utility loaders (added v0.6.0)
        "auto32k", "auto-32k", "thirty2k", "fdpclient", "fdp-client",
        "atomic-loader", "spirit-client", "spiritclient",
        "nighthawk", "nightclient", "sky-client", "skyclient",
        "polywrap", "hexware-loader", "hexwareloader",
        "crystalware", "crystal-client", "crystalclient",
        "ghosthack", "ghost-hack", "blackbox-client", "blackboxclient",
        "zoot", "zoot-client", "zootclient",
        "syrup-client", "syrupclient", "uno-client",
        "ravenb4", "tomate-client", "tomateclient", "ronin-client",
        "ronin-loader", "kosen-client", "kosenclient",
        "trex-client", "trexclient", "verge-client", "vergeclient",
        "rapid-client", "rapidclient", "lunar-cheat", "lunarcheat",
        "feather-cheat", "feathercheat", "badlion-cheat", "badlioncheat",
        "essential-cheat", "schizoid", "schizoid-client",
        "rosehip", "rosehip-client",

        // Ghost-only / pixelmon-like cheat utilities people often forget
        "x-ray-mod", "xray-mod", "xraymod",
        "world-downloader", "worlddownloader", "ore-finder",

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

        // 2025-2026 cheat clients seen on screenshare (added v0.9.5)
        "koid", "koid-client", "koidclient",
        "atermys", "atermys-client", "atermysclient", "atermys-loader",
        "slinky", "slinky-gg", "slinkyloader", "slinky-loader",
        "pluto", "plutosolutions", "pluto-solutions",
        "orion-client", "orionclient", "orion-loader",
        "zenith-client", "zenithclient",
        "vivid-client", "vividclient",
        "solaris-client", "solarisclient",
        "trident-client", "tridentclient",
        "nexus-client", "nexusclient",
        "astrolabe", "astrolabe-client",
        "venom-client", "venomclient",
        "mistral-client", "mistralclient",
        "raptor-client", "raptorclient",
        "inferno-client", "infernoclient",
        "polaris-client", "polarisclient",
        "eclipse-cheat", "eclipsecheat",
        "obsidian-client", "obsidianclient",
        "titan-client", "titanclient", "titan-loader",
        "thunder-client-mc", "thunderclient-mc",
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

        // Newer / less-known cheat shops & client websites (added v0.6.0)
        "alpine-client.com",
        "alpineclient.com",
        "expensive-client.org",
        "expensiveclient.org",
        "future.nl",
        "moho-client.com",
        "drowned.gg",
        "matrix.vg",
        "matrix-client.net",
        "hexware.io",
        "hexware.cc",
        "sigmajek.cc",
        "ghost-client.cc",
        "killaura.gg",
        "atomicclient.cc",
        "atomic-client.cc",
        "fdpclient.com",
        "nightclient.cc",
        "skyclient.cc",
        "rapidclient.org",
        "tomateclient.com",
        "rosehipclient.com",
        "schizoidclient.com",

        // GitHub mirrors that consistently host/build cheat clients (substring match)
        "/wurst-client",
        "/wurst-imperium",
        "/meteordevelopment",
        "/liquidbounce",
        "/rusherhack",
        "/bleach-hack",

        // 2025-2026 distribution sites / Telegram mirrors (added v0.9.5)
        "slinky.gg",
        "t.me/plutosolutions",
        "plutosolutions.com",
        "atermys.com",
        "atermys.gg",
        "atermys.cc",
        "koidclient.com",
        "koid.gg",
        "orion-client.com",
        "zenithclient.cc",
        "vividclient.cc",
        "solarisclient.org",
        "tridentclient.cc",
        "nexusclient.cc",
        "venomclient.cc",
        "infernoclient.cc",
        "obsidianclient.cc",
        "titan-client.cc",
        "eclipsecheat.io",
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

        // Newer markers (added v0.6.0)
        "sneakaura", "anti-aim", "antiaim", "auto-fish", "autofish",
        "ghosthand", "ghost-hand", "block-esp", "blockesp",
        "tnt-aura", "tntaura", "auto-place", "autoplace",
        "auto-disconnect", "autodisconnect",
        "modules/exploit/", "modules/world/", "modules/player/",
        "obfuscated/aaaa", "obfuscated/bbbb",
        "cheat/module", "cheat/modules", "client/module",

        // Java agent-class path fragments that routinely appear in cheat
        // agents (added v0.9.5). These are package-path substrings — we
        // match them against zip entry names (MinecraftScanner) and
        // agent-class attribute values (JavaAgentScanner).
        "net/java/f/", "dev/koid/", "gg/slinky/", "net/atermys/",
        "premain", "agentmain", "lang/instrument/",
        "net/weavemc/", "net/doomsday/", "com/atermys/",
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

        // Added v0.6.0 — external loaders / standalone clients
        "atomicloader",  "atomic-loader",
        "spiritloader",  "spirit-loader",
        "fdploader",     "fdp-loader",
        "nighthawkloader",
        "skyloader",     "sky-loader",
        "polywrap",
        "rapidloader",   "rapid-loader",
        "tomateloader",  "tomate-loader",
        "schizoidloader",
        "ghostloader",   "ghost-loader",
    };

    /// <summary>
    /// Heuristic: process names that should NEVER match — common system /
    /// development tools whose names happen to be substrings of cheat names
    /// (e.g. "future.exe" could be the legitimate Future game launcher).
    /// Used to short-circuit obvious false positives in <see cref="ExternalCheatProcessNames"/>.
    /// </summary>
    public static readonly string[] WellKnownBenignProcesses =
    {
        "discord", "discordcanary", "discordptb", "discorddevelopment",
        "spotify", "steam", "steamservice", "steamwebhelper",
        "javaw", "java", "javaws",
        "explorer", "rundll32", "svchost", "system",
        "chrome", "firefox", "msedge", "opera", "brave",
        "msteams", "teams", "slack", "code", "devenv",
        "obs64", "obs32", "obs", "streamlabs",
        "minecraftlauncher", "minecraft launcher",
        "tlauncher",
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

    /// <summary>
    /// Stricter version of <see cref="MatchKeywords"/> for matching short process
    /// names against <see cref="ExternalCheatProcessNames"/>. Requires the keyword
    /// to be either an exact match or appear as a token surrounded by non-letter
    /// characters. Avoids "future.exe" (game launcher) hitting on "future" cheat
    /// keyword too eagerly.
    /// </summary>
    public static IEnumerable<string> MatchProcessName(string processName, IEnumerable<string> keywords)
    {
        if (string.IsNullOrEmpty(processName)) yield break;

        var lower = processName.ToLowerInvariant();
        foreach (var benign in WellKnownBenignProcesses)
        {
            if (string.Equals(lower, benign, StringComparison.OrdinalIgnoreCase))
                yield break;
        }

        foreach (var kw in keywords)
        {
            if (string.Equals(lower, kw, StringComparison.OrdinalIgnoreCase))
            {
                yield return kw;
                continue;
            }
            // Token-boundary match: kw appears with non-letter chars on each side
            // (or string boundary). This filters benign substrings like "ares"
            // matching "share" or "future" matching "futureproof".
            int idx = lower.IndexOf(kw, StringComparison.OrdinalIgnoreCase);
            while (idx >= 0)
            {
                bool leftOk  = idx == 0 || !char.IsLetterOrDigit(lower[idx - 1]);
                int  end     = idx + kw.Length;
                bool rightOk = end == lower.Length || !char.IsLetterOrDigit(lower[end]);
                if (leftOk && rightOk) { yield return kw; break; }
                idx = lower.IndexOf(kw, idx + 1, StringComparison.OrdinalIgnoreCase);
            }
        }
    }
}
