using System;
using System.Collections.Generic;

namespace McSsCheck.Data;

/// <summary>
/// Deterministic fingerprints for known cheat clients/loaders that survive
/// trivial obfuscation (renaming the file, repacking the .zip, etc.).
///
/// Two layers, listed weakest-effort to strongest:
///   1. <see cref="BinaryMarkers"/> — distinctive ASCII/UTF-16 strings that
///      appear inside the PE / jar / zip bytes (PDB paths, branding banners,
///      exported function names, log messages). Matched as a substring of
///      the raw file bytes treated as Latin-1, with a parallel UTF-16-LE
///      pass to catch widechar PE resources. Strings are picked to be
///      *unique to that cheat* — avoid generic "KillAura" tokens that could
///      legitimately appear elsewhere.
///   2. <see cref="KnownCheatHashes"/> — full-file SHA-256 of every cheat
///      sample we've seen on a real screenshare. Renaming the file does
///      nothing; this only fails when the cheat author ships a new build.
/// </summary>
internal static class CheatFingerprints
{
    /// <summary>
    /// SHA-256 (lowercase hex, no separators) → human-readable cheat label.
    /// Submitted by SS staff on real captures; add new hashes here when you
    /// see a new sample.
    /// </summary>
    public static readonly Dictionary<string, string> KnownCheatHashes = new(StringComparer.OrdinalIgnoreCase)
    {
        // Atermys Client loader (renamed "Anydesk.exe" by player on 2026-05).
        // Original PE PDB path: ...\atermys\atermys-main\x64\Release\atermys loader.pdb
        ["8702d9f15e266f71543777d66555f54c9e0c32ca7ec44fa5f63eff085a74aeea"] = "Atermys Client (loader)",

        // Doomsday Client jar shipped through a LabyMod-targeting Java
        // agent. Premain-Class: net.java.f, opaque 1-letter classes,
        // encrypted "000" payload. Confirmed by SS staff 2026-05.
        ["ed2e20f482d8bde1c94b036d9ef43ea8be9a59214fbb9c7803653fb5f854a3b0"] = "Doomsday Client (jar)",

        // Slinky.gg crack distribution — outer .zip from t.me/plutosolutions.
        ["505d1b351e058bef471dac95fc21b46dcfc2a30479eef91533b2eff85a8654c5"] = "Slinky.gg crack (zip)",

        // Slinky.gg crack — inner slinkyloader.exe.
        ["cef5b60321f17991400a19072052535638c0a5c02d338234686552deadeea82e"] = "Slinky.gg crack (loader)",
    };

    /// <summary>
    /// One byte-content marker that uniquely identifies a cheat. Pattern is
    /// matched against the raw file bytes as ASCII *and* as UTF-16-LE.
    ///
    /// <para><b>Picking patterns:</b> only add strings that are unique
    /// enough to not appear in legitimate software. A literal client name
    /// like <c>"Atermys Client"</c> is fine. A bare class name like
    /// <c>"AimAssist"</c> is NOT — it can show up in unrelated code.</para>
    /// </summary>
    public sealed record BinaryMarker(string CheatName, string Variant, string Pattern);

    public static readonly BinaryMarker[] BinaryMarkers =
    {
        // ---------------- Atermys Client ----------------
        new("Atermys Client", "loader-banner", "WELCOME TO ATERMYS"),
        new("Atermys Client", "inject-banner", "INJECTED ATERMYS"),
        new("Atermys Client", "branding",      "ATERMYS CLIENT"),
        new("Atermys Client", "rtti-api",      "AtermysAPI"),
        new("Atermys Client", "rtti-injector", "ProcessInjector@AtermysAPI"),
        new("Atermys Client", "config-path",   @"\Atermys\configs\"),
        new("Atermys Client", "friends-path",  @"\Atermys\friends.json"),
        new("Atermys Client", "pdb-loader",    "atermys loader.pdb"),
        new("Atermys Client", "pdb-internal",  "atermys internal.pdb"),
        new("Atermys Client", "ss-message",    "you may not be safe in screenshare"),

        // ---------------- Slinky.gg ----------------
        new("Slinky.gg",      "crack-loader",   "slinky.gg crack loader"),
        new("Slinky.gg",      "library-dll",    "slinky_library.dll"),
        new("Slinky.gg",      "hook-dll",       "slinkyhook.dll"),
        new("Slinky.gg",      "init-export",    "slinky_init"),
        new("Slinky.gg",      "inject-banner",  "Slinky has been injected"),
        new("Slinky.gg",      "crack-credit",   "cracked by mrnv"),
        new("Slinky.gg",      "pluto-distrib",  "PlutoSolutions"),
        new("Slinky.gg",      "pluto-channel",  "t.me/plutosolutions"),

        // ---------------- Other well-known clients ----------------
        // Banner / branding strings unique to each client. Only patterns we
        // are confident appear *only* in that cheat go here.
        new("Wurst Client",   "branding",       "Wurst Client"),
        new("Sigma Client",   "branding",       "SigmaClient"),
        new("Sigma Client",   "5-banner",       "Sigma 5"),
        new("Impact Client",  "branding",       "Impact Client"),
        new("LiquidBounce",   "branding",       "LiquidBounce"),
        new("RusherHack",     "branding",       "RusherHack"),
        new("Vape Client",    "v4-banner",      "Vape V4"),
        new("Vape Client",    "lite-banner",    "VapeLite"),
        new("Aristois",       "branding",       "Aristois"),
        new("Doomsday",       "branding",       "Doomsday Client"),
        new("Salhack",        "branding",       "Salhack"),
        new("Konas Client",   "branding",       "Konas Client"),
        new("Wolfram Client", "branding",       "Wolfram Client"),
        new("BleachHack",     "branding",       "BleachHack"),
        new("Future Client",  "branding",       "Future Client"),
        new("Phobos",         "branding",       "Phobos Client"),
        new("Moon Client",    "branding",       "Moon Client"),
        new("Celestial",      "branding",       "Celestial Client"),
        new("Kosen Client",   "branding",       "Kosen Client"),
        new("Drowned Client", "branding",       "Drowned Client"),

        // Generic injector library strings — common in cheat .exe loaders.
        // Marked as generic so the report can flag them as "external loader"
        // even if we don't recognise the specific cheat.
        new("Generic Loader", "blackbone-rtti", "blackbone"),
        new("Generic Loader", "vmt-hook",       "VMTHook"),

        // ---------------- Added v0.9.5 ----------------
        // Koid Client — 2025-2026 ghost client. Agent-style jar.
        new("Koid Client",    "branding",       "Koid Client"),
        new("Koid Client",    "class-prefix",   "dev/koid/"),
        new("Koid Client",    "agent-ident",    "koid-agent"),
        new("Koid Client",    "logger-tag",     "[Koid]"),

        // Weave MC — popular open-source cheat-mod loader (java agent).
        new("Weave Loader",   "branding",       "Weave Loader"),
        new("Weave Loader",   "class-prefix",   "net/weavemc/"),
        new("Weave Loader",   "loader-tag",     "weave-loader-agent"),

        // Orion Client (rebrand of Future, circulated 2025).
        new("Orion Client",   "branding",       "Orion Client"),
        new("Orion Client",   "legacy-note",    "orion-based on future"),

        // Zenith Client — distributed via Discord 2026.
        new("Zenith Client",  "branding",       "Zenith Client"),

        // Atermys extra markers — older & newer loader builds.
        new("Atermys Client", "config-header",  "atermys-config-v"),
        new("Atermys Client", "overlay-title",  "atermys overlay"),

        // Slinky.gg extra markers — newer packaged builds.
        new("Slinky.gg",      "injector-tag",   "SlinkyInjector"),
        new("Slinky.gg",      "config-marker",  "slinky_config"),

        // Doomsday extra — premain class signature seen on recent builds.
        new("Doomsday",       "premain-class",  "net.java.f"),
    };
}
