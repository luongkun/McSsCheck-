using System;

namespace McSsCheck.Models;

public enum ModVerification { Unknown, Verified, NotVerified, Skipped }

/// <summary>One mod (jar) discovered under <c>.minecraft/mods/</c> or a versions/ folder.</summary>
public sealed class ModEntry
{
    public string FileName  { get; init; } = "";
    public string FilePath  { get; init; } = "";
    public long   Size      { get; init; }
    public DateTime Modified { get; init; }
    public string? Sha1     { get; init; }
    public string? Sha256   { get; init; }

    /// <summary>Set by <c>ModrinthChecker</c> after the lookup completes.</summary>
    public ModVerification Verification { get; set; } = ModVerification.Unknown;

    /// <summary>"Modrinth", "CurseForge", … — populated when a registry recognises the hash.</summary>
    public string? RegistryName { get; set; }

    /// <summary>Project title from the registry (e.g. "Sodium").</summary>
    public string? RegistryTitle { get; set; }

    /// <summary>Public download URL from the registry, if any.</summary>
    public string? RegistryDownloadUrl { get; set; }

    public string? Notes { get; set; }
}
