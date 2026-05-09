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
/// We intentionally do NOT read the chat / message cache / token cache.
/// </summary>
public sealed record DiscordInstall(
    string Variant,            // "Discord", "DiscordPTB", "DiscordCanary", "DiscordDevelopment"
    string InstallPath,
    string? Version  = null,
    bool   IsRunning = false);

/// <summary>
/// Discord account that has signed into the client on this machine. The
/// account information is pulled from Discord's own
/// <c>Local Storage\leveldb\_remoteAuth_recentAccounts</c> entry — exactly
/// the list Discord renders in its own "Switch account" menu.
///
/// Only the public fields (user ID / username / avatar hash) are read; we
/// never touch tokens, DMs, or session data.
/// </summary>
public sealed record DiscordAccount(
    string UserId,             // snowflake (public)
    string Username,           // username at the time of last login
    string? GlobalName  = null, // display name (Discord 2023+ rename)
    string? AvatarHash  = null, // for cdn.discordapp.com URL building
    string  ClientVariant = "Discord");
