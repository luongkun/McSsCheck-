using System;
using System.Collections.Generic;

namespace McSsCheck.Models;

/// <summary>Alternative Minecraft accounts found on the machine (vanilla launcher / TLauncher / Lunar / …).</summary>
public sealed record MinecraftAccount(
    string Source,             // launcher_profiles / TLauncher / Lunar / …
    string Username,
    string? Uuid       = null,
    string? AccountType = null, // "msa", "mojang", "offline", …
    string? FilePath   = null,
    DateTime? LastUsed = null);

/// <summary>
/// Information about Discord client installation (NOT account data).
/// We intentionally do NOT read the leveldb / chat / token cache.
/// </summary>
public sealed record DiscordInstall(
    string Variant,            // "Discord", "DiscordPTB", "DiscordCanary", "DiscordDevelopment"
    string InstallPath,
    string? Version  = null,
    bool   IsRunning = false);
