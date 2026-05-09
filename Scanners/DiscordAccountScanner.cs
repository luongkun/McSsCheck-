using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text;
using System.Text.RegularExpressions;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

/// <summary>
/// Reads the Discord client's own "recent accounts" list from its
/// <c>Local Storage\leveldb</c> key/value store and surfaces them as
/// <see cref="DiscordAccount"/> entries on the report. Discord renders the
/// same list in its in-app "Switch account" menu — i.e. these are the
/// accounts the player has logged in to on this machine.
///
/// We scan only the leveldb <c>.log</c> files and the <c>CURRENT</c>/MANIFEST,
/// because <c>.ldb</c> tables are snappy-compressed and would need a real
/// leveldb reader. The <c>.log</c> file is uncompressed and contains the
/// most recent state in plain UTF-8, which is exactly what we want.
///
/// What we read:  <c>"id":"&lt;snowflake&gt;"</c>, <c>"username"</c>,
///                <c>"global_name"</c>, <c>"avatar"</c>.
/// What we DO NOT read: tokens, emails, DMs, chat messages, friend lists.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class DiscordAccountScanner
{
    public const string SourceName = "DiscordAccountScanner";

    public static void Run(SessionReport report, SessionReport.Section section)
    {
        ConsoleUI.Section("Discord accounts (signed-in on this machine)");

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var roots = new (string Variant, string Path)[]
        {
            ("Discord",            Path.Combine(appData, "discord",            "Local Storage", "leveldb")),
            ("DiscordPTB",         Path.Combine(appData, "discordptb",         "Local Storage", "leveldb")),
            ("DiscordCanary",      Path.Combine(appData, "discordcanary",      "Local Storage", "leveldb")),
            ("DiscordDevelopment", Path.Combine(appData, "discorddevelopment", "Local Storage", "leveldb")),
        };

        // Dedupe by user ID so the same account showing up in both stable
        // Discord and DiscordPTB doesn't render twice.
        var found = new Dictionary<string, DiscordAccount>(StringComparer.Ordinal);
        int filesScanned = 0;

        foreach (var (variant, root) in roots)
        {
            if (!Directory.Exists(root)) continue;

            foreach (var file in EnumerateScannableFiles(root))
            {
                filesScanned++;
                string text;
                try
                {
                    var bytes = File.ReadAllBytes(file);
                    // Decode liberally — the leveldb log is mostly ASCII for
                    // the JSON portions; any binary header bytes simply turn
                    // into replacement chars and don't break the regex.
                    text = Encoding.UTF8.GetString(bytes);
                }
                catch (Exception ex)
                {
                    ConsoleUI.Dim($"  (could not read {file}: {ex.Message})");
                    continue;
                }

                // Strategy 1 — Discord's _remoteAuth_recentAccounts key
                // stores a JSON array describing every account that has
                // signed in. Format: [{"userId":"…","name":"…","avatarHash":"…"}, …]
                foreach (Match m in RemoteAuthAccount.Matches(text))
                {
                    var id = m.Groups["id"].Value;
                    if (!IsSnowflake(id)) continue;
                    if (!found.ContainsKey(id))
                    {
                        found[id] = new DiscordAccount(
                            UserId: id,
                            Username: Unescape(m.Groups["name"].Value),
                            AvatarHash: m.Groups["avatar"].Success && m.Groups["avatar"].Value.Length > 0
                                          ? m.Groups["avatar"].Value : null,
                            ClientVariant: variant);
                    }
                }

                // Strategy 2 — fallback: scan for inline user objects of the
                // form {"id":"…","username":"…",…,"avatar":"…"} that
                // Discord's redux state caches. Useful when remoteAuth has
                // been pruned but the Multi Account Store still has it.
                foreach (Match m in InlineUserObject.Matches(text))
                {
                    var id = m.Groups["id"].Value;
                    if (!IsSnowflake(id)) continue;
                    var username = Unescape(m.Groups["username"].Value);
                    if (string.IsNullOrEmpty(username)) continue;

                    if (!found.TryGetValue(id, out var existing))
                    {
                        found[id] = new DiscordAccount(
                            UserId: id,
                            Username: username,
                            GlobalName: m.Groups["global"].Success && m.Groups["global"].Value.Length > 0
                                          ? Unescape(m.Groups["global"].Value) : null,
                            AvatarHash: m.Groups["avatar"].Success && m.Groups["avatar"].Value.Length > 0
                                          ? m.Groups["avatar"].Value : null,
                            ClientVariant: variant);
                    }
                    else
                    {
                        // Existing entry came from remoteAuth which doesn't
                        // know global_name — backfill it from the inline
                        // object if the new one has it.
                        if (existing.GlobalName == null && m.Groups["global"].Success
                            && m.Groups["global"].Value.Length > 0)
                        {
                            found[id] = existing with
                            {
                                GlobalName = Unescape(m.Groups["global"].Value)
                            };
                        }
                    }
                }
            }
        }

        if (filesScanned == 0)
        {
            ConsoleUI.Ok("No Discord local-storage to scan (Discord may not be installed).");
            return;
        }

        if (found.Count == 0)
        {
            ConsoleUI.Ok($"No signed-in Discord accounts found ({filesScanned} leveldb file(s) scanned).");
            return;
        }

        report.DiscordAccounts.AddRange(found.Values
            .OrderBy(a => a.ClientVariant, StringComparer.Ordinal)
            .ThenBy(a => a.Username,       StringComparer.OrdinalIgnoreCase));

        foreach (var a in report.DiscordAccounts)
        {
            ConsoleUI.Info($"  {a.Username}  id={a.UserId}  variant={a.ClientVariant}");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Info,
                Title: $"Discord account: {a.Username}",
                Detail: $"id={a.UserId}, variant={a.ClientVariant}"
                      + (a.GlobalName != null ? $", display='{a.GlobalName}'" : "")
                      + (a.AvatarHash != null ? $", avatar={a.AvatarHash}" : ""),
                Tags: new[] { "discord-account" }));
        }
    }

    /// <summary>
    /// Enumerate the leveldb files we can usefully scan. We deliberately
    /// skip <c>.ldb</c> (snappy-compressed sstables) and the manifest, and
    /// only look at the active write-ahead log <c>.log</c> file.
    /// </summary>
    private static IEnumerable<string> EnumerateScannableFiles(string root)
    {
        IEnumerable<string> safe(string pattern)
        {
            try { return Directory.EnumerateFiles(root, pattern, SearchOption.TopDirectoryOnly); }
            catch { return Array.Empty<string>(); }
        }
        return safe("*.log");
    }

    private static bool IsSnowflake(string s) => s.Length is >= 17 and <= 20
        && s.All(char.IsDigit);

    /// <summary>Tiny JSON-string unescape that handles only the cases we care about (\\, \", \n).</summary>
    private static string Unescape(string s)
    {
        if (s.IndexOf('\\') < 0) return s;
        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (c == '\\' && i + 1 < s.Length)
            {
                var n = s[++i];
                sb.Append(n switch { '\\' => '\\', '"' => '"', 'n' => '\n', 't' => '\t', '/' => '/', _ => n });
            }
            else sb.Append(c);
        }
        return sb.ToString();
    }

    // {"userId":"123…","name":"foo","avatarHash":"abc"}  — order can vary so we
    // accept name before/after userId. avatarHash optional.
    private static readonly Regex RemoteAuthAccount = new(
        @"""userId""\s*:\s*""(?<id>\d{17,20})""\s*,\s*""[a-zA-Z]+""\s*:\s*""(?<name>(?:\\""|[^""])*)""(?:\s*,\s*""avatarHash""\s*:\s*""(?<avatar>[a-fA-F0-9_]+)?"")?",
        RegexOptions.Compiled);

    // {"id":"123…","username":"foo",…,"global_name":"Foo",…,"avatar":"abc"}
    // We allow up to ~400 chars between fields so the regex doesn't run away
    // on huge JSON payloads.
    private static readonly Regex InlineUserObject = new(
        @"""id""\s*:\s*""(?<id>\d{17,20})""[^{}]{0,400}?""username""\s*:\s*""(?<username>(?:\\""|[^""])*)""(?:[^{}]{0,400}?""global_name""\s*:\s*""(?<global>(?:\\""|[^""])*)"")?(?:[^{}]{0,400}?""avatar""\s*:\s*""(?<avatar>[a-fA-F0-9_]+)?"")?",
        RegexOptions.Compiled);
}
