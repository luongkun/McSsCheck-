using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text.Json;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

/// <summary>
/// Discovers alternative Minecraft accounts that exist on the machine by
/// parsing well-known launcher profile files. We only read the username
/// fields and (when present) the UUID; we never read passwords, refresh
/// tokens, access tokens, or session caches.
///
/// Sources:
///   - vanilla launcher: <c>%APPDATA%\.minecraft\launcher_profiles.json</c>
///   - vanilla launcher (newer): <c>%APPDATA%\.minecraft\launcher_accounts.json</c>
///   - TLauncher: <c>%APPDATA%\.minecraft\TlauncherProfiles.json</c>
///   - Lunar Client: <c>%USERPROFILE%\.lunarclient\settings\game\accounts.json</c>
///   - Feather Client: <c>%APPDATA%\.feather\accounts.json</c>
///   - Badlion Client: <c>%APPDATA%\.minecraft\badlion-settings.json</c>
///   - Prism / MultiMC: <c>accounts.json</c> under their data directory
/// </summary>
[SupportedOSPlatform("windows")]
internal static class AltAccountScanner
{
    public const string SourceName = "AltAccountScanner";

    public static void Run(SessionReport report, SessionReport.Section section)
    {
        ConsoleUI.Section("Alternative Minecraft accounts");

        var roaming  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var profile  = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var before = report.McAccounts.Count;

        TryVanillaProfiles  (Path.Combine(roaming,  ".minecraft", "launcher_profiles.json"), report);
        TryVanillaAccounts  (Path.Combine(roaming,  ".minecraft", "launcher_accounts.json"), report);
        TryTLauncher        (Path.Combine(roaming,  ".minecraft", "TlauncherProfiles.json"), report);
        TryLunar            (Path.Combine(profile,  ".lunarclient", "settings", "game", "accounts.json"), report);
        TryFeather          (Path.Combine(roaming,  ".feather", "accounts.json"), report);
        TryBadlion          (Path.Combine(roaming,  ".minecraft", "badlion-settings.json"), report);
        TryPrism            (Path.Combine(roaming,  "PrismLauncher", "accounts.json"), report);
        TryPrism            (Path.Combine(localApp, "Programs", "PrismLauncher", "accounts.json"), report);
        TryPrism            (Path.Combine(roaming,  "MultiMC", "accounts.json"), report);

        var added = report.McAccounts.Count - before;
        if (added == 0)
        {
            ConsoleUI.Ok("No alt account profiles found in standard locations.");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Info,
                Title: "No alt accounts detected",
                Detail: "Inspected vanilla, TLauncher, Lunar, Feather, Badlion, Prism, MultiMC profile files."));
            return;
        }

        ConsoleUI.Info($"  found {added} account profile(s)");
        var grouped = report.McAccounts
            .GroupBy(a => a.Source)
            .OrderBy(g => g.Key);
        foreach (var g in grouped)
        {
            foreach (var acc in g)
            {
                ConsoleUI.Info($"  {g.Key} : {acc.Username}{(acc.AccountType != null ? " [" + acc.AccountType + "]" : "")}");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Info,
                    Title: $"{g.Key}: {acc.Username}",
                    Detail: $"type={acc.AccountType ?? "?"}  uuid={acc.Uuid ?? "?"}",
                    FilePath: acc.FilePath,
                    Tags: new[] { g.Key.ToLowerInvariant().Replace(' ', '-') }));
            }
        }

        if (added > 1)
        {
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Warn,
                Title: $"{added} Minecraft account profiles detected",
                Detail: "Multiple alt accounts on a single machine isn't proof of cheating but is a common screenshare red flag worth asking about."));
        }
    }

    // ---------------------------------------------------------------------

    private static void TryVanillaProfiles(string path, SessionReport report)
    {
        if (!File.Exists(path)) return;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var root = doc.RootElement;
            if (root.TryGetProperty("authenticationDatabase", out var db))
            {
                foreach (var prop in db.EnumerateObject())
                {
                    var obj = prop.Value;
                    if (obj.TryGetProperty("profiles", out var profiles))
                    {
                        foreach (var p in profiles.EnumerateObject())
                        {
                            var name = p.Value.TryGetProperty("displayName", out var n) ? n.GetString() : null;
                            if (!string.IsNullOrEmpty(name))
                                report.McAccounts.Add(new MinecraftAccount(
                                    Source: "launcher_profiles",
                                    Username: name!,
                                    Uuid: p.Name,
                                    AccountType: obj.TryGetProperty("userid", out _) ? "mojang" : "msa",
                                    FilePath: path));
                        }
                    }
                }
            }
        }
        catch (Exception ex) { ConsoleUI.Dim($"  cannot parse {path}: {ex.Message}"); }
    }

    private static void TryVanillaAccounts(string path, SessionReport report)
    {
        if (!File.Exists(path)) return;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            if (doc.RootElement.TryGetProperty("accounts", out var accs))
            {
                foreach (var acc in accs.EnumerateObject())
                {
                    var v = acc.Value;
                    var prof = v.TryGetProperty("minecraftProfile", out var mp) ? mp : default;
                    var name = prof.ValueKind == JsonValueKind.Object && prof.TryGetProperty("name", out var n)
                        ? n.GetString() : null;
                    var uuid = prof.ValueKind == JsonValueKind.Object && prof.TryGetProperty("id", out var i)
                        ? i.GetString() : null;
                    var type = v.TryGetProperty("type", out var t) ? t.GetString() : null;
                    if (!string.IsNullOrEmpty(name))
                        report.McAccounts.Add(new MinecraftAccount(
                            Source: "launcher_accounts",
                            Username: name!, Uuid: uuid, AccountType: type, FilePath: path));
                }
            }
        }
        catch (Exception ex) { ConsoleUI.Dim($"  cannot parse {path}: {ex.Message}"); }
    }

    private static void TryTLauncher(string path, SessionReport report)
    {
        if (!File.Exists(path)) return;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            if (doc.RootElement.TryGetProperty("accounts", out var accs))
            {
                foreach (var acc in accs.EnumerateArray())
                {
                    var name = acc.TryGetProperty("username", out var n) ? n.GetString()
                             : acc.TryGetProperty("displayName", out var d) ? d.GetString() : null;
                    var uuid = acc.TryGetProperty("uuid", out var u) ? u.GetString() : null;
                    var type = acc.TryGetProperty("type", out var t) ? t.GetString() : null;
                    if (!string.IsNullOrEmpty(name))
                        report.McAccounts.Add(new MinecraftAccount(
                            Source: "TLauncher",
                            Username: name!, Uuid: uuid, AccountType: type, FilePath: path));
                }
            }
            // Older TLauncher format stores raw username in "user" key.
            else if (doc.RootElement.TryGetProperty("user", out var user) &&
                     user.ValueKind == JsonValueKind.String)
            {
                report.McAccounts.Add(new MinecraftAccount(
                    Source: "TLauncher",
                    Username: user.GetString() ?? "?",
                    AccountType: "tlauncher", FilePath: path));
            }
        }
        catch (Exception ex) { ConsoleUI.Dim($"  cannot parse {path}: {ex.Message}"); }
    }

    private static void TryLunar(string path, SessionReport report)
    {
        if (!File.Exists(path)) return;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            // Lunar accounts.json shape varies; we look for any property
            // that looks like a username field on an account object.
            foreach (var node in EnumerateAccountObjects(doc.RootElement))
            {
                var name = TryString(node, "username") ?? TryString(node, "displayName") ?? TryString(node, "name");
                var uuid = TryString(node, "uuid") ?? TryString(node, "id");
                var type = TryString(node, "type") ?? TryString(node, "accountType");
                if (!string.IsNullOrEmpty(name))
                    report.McAccounts.Add(new MinecraftAccount(
                        Source: "Lunar Client",
                        Username: name!, Uuid: uuid, AccountType: type, FilePath: path));
            }
        }
        catch (Exception ex) { ConsoleUI.Dim($"  cannot parse {path}: {ex.Message}"); }
    }

    private static void TryFeather(string path, SessionReport report)
    {
        if (!File.Exists(path)) return;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            foreach (var node in EnumerateAccountObjects(doc.RootElement))
            {
                var name = TryString(node, "username") ?? TryString(node, "name");
                var uuid = TryString(node, "uuid") ?? TryString(node, "id");
                if (!string.IsNullOrEmpty(name))
                    report.McAccounts.Add(new MinecraftAccount(
                        Source: "Feather Client",
                        Username: name!, Uuid: uuid, FilePath: path));
            }
        }
        catch (Exception ex) { ConsoleUI.Dim($"  cannot parse {path}: {ex.Message}"); }
    }

    private static void TryBadlion(string path, SessionReport report)
    {
        if (!File.Exists(path)) return;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            foreach (var node in EnumerateAccountObjects(doc.RootElement))
            {
                var name = TryString(node, "username") ?? TryString(node, "displayName") ?? TryString(node, "name");
                var uuid = TryString(node, "uuid") ?? TryString(node, "id");
                if (!string.IsNullOrEmpty(name))
                    report.McAccounts.Add(new MinecraftAccount(
                        Source: "Badlion Client",
                        Username: name!, Uuid: uuid, FilePath: path));
            }
        }
        catch (Exception ex) { ConsoleUI.Dim($"  cannot parse {path}: {ex.Message}"); }
    }

    private static void TryPrism(string path, SessionReport report)
    {
        if (!File.Exists(path)) return;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            if (doc.RootElement.TryGetProperty("accounts", out var accs) &&
                accs.ValueKind == JsonValueKind.Array)
            {
                foreach (var acc in accs.EnumerateArray())
                {
                    string? name = TryString(acc, "username");
                    string? uuid = TryString(acc, "profile.id") ?? TryString(acc, "id");
                    string? type = TryString(acc, "type");
                    if (acc.TryGetProperty("profile", out var prof) && prof.ValueKind == JsonValueKind.Object)
                    {
                        name ??= TryString(prof, "name");
                        uuid ??= TryString(prof, "id");
                    }
                    if (!string.IsNullOrEmpty(name))
                        report.McAccounts.Add(new MinecraftAccount(
                            Source: Path.GetFileName(Path.GetDirectoryName(path)) ?? "Prism",
                            Username: name!, Uuid: uuid, AccountType: type, FilePath: path));
                }
            }
        }
        catch (Exception ex) { ConsoleUI.Dim($"  cannot parse {path}: {ex.Message}"); }
    }

    // ---------------------------------------------------------------------

    /// <summary>
    /// Yield every JSON object that appears to describe an account: i.e.,
    /// every object that contains at least a "username" / "name" / "displayName" property.
    /// Walks arrays and nested object values to a small depth.
    /// </summary>
    private static IEnumerable<JsonElement> EnumerateAccountObjects(JsonElement root)
    {
        var stack = new Stack<(JsonElement Node, int Depth)>();
        stack.Push((root, 0));
        while (stack.Count > 0)
        {
            var (node, depth) = stack.Pop();
            if (depth > 5) continue;

            switch (node.ValueKind)
            {
                case JsonValueKind.Object:
                    if (LooksLikeAccount(node)) yield return node;
                    foreach (var p in node.EnumerateObject())
                    {
                        if (p.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
                            stack.Push((p.Value, depth + 1));
                    }
                    break;
                case JsonValueKind.Array:
                    foreach (var el in node.EnumerateArray())
                        if (el.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
                            stack.Push((el, depth + 1));
                    break;
            }
        }

        static bool LooksLikeAccount(JsonElement obj)
        {
            foreach (var p in obj.EnumerateObject())
            {
                var n = p.Name.ToLowerInvariant();
                if (n == "username" || n == "displayname" || n == "name")
                    if (p.Value.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(p.Value.GetString()))
                        return true;
            }
            return false;
        }
    }

    private static string? TryString(JsonElement obj, string key)
    {
        if (obj.ValueKind != JsonValueKind.Object) return null;
        if (!obj.TryGetProperty(key, out var v)) return null;
        return v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    }
}
