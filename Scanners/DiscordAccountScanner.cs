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
/// Reads the Discord client's "recent accounts" / multi-account list from
/// its Chromium-style storage (Local Storage leveldb, Session Storage,
/// IndexedDB) and surfaces every signed-in account as a
/// <see cref="DiscordAccount"/> entry on the report. Discord renders the
/// same data in its in-app "Switch account" menu — i.e. these are the
/// accounts the player has logged in to on this machine.
///
/// We deliberately do *not* parse the leveldb format properly: doing so
/// would require snappy decompression (and rebuilding sstables in memory).
/// Instead we read every <c>.log / .ldb</c> file as a flat byte blob and
/// pull JSON fragments out by regex. This works because:
///   - leveldb log files are uncompressed (write-ahead log).
///   - leveldb sstables (<c>.ldb</c>) are snappy-framed: each block has
///     literal byte runs interleaved with copy commands, and short JSON
///     keys / values survive the framing intact most of the time.
///   - Session Storage is plain key=value with a 1-byte type prefix.
///
/// What we read:  <c>"id":"&lt;snowflake&gt;"</c>, <c>"username"</c>,
///                <c>"global_name"</c>, <c>"avatar"</c>, <c>"userId"</c>.
/// What we DO NOT read: tokens, emails, DMs, chat messages, friend lists.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class DiscordAccountScanner
{
    public const string SourceName = "DiscordAccountScanner";

    /// <summary>Cap on how many bytes we slurp from a single file.</summary>
    private const int PerFileByteBudget = 16 * 1024 * 1024;

    public static void Run(SessionReport report, SessionReport.Section section)
    {
        ConsoleUI.Section("Discord accounts (signed-in on this machine)");

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var variants = new (string Variant, string AppRoot)[]
        {
            ("Discord",            Path.Combine(appData, "discord")),
            ("DiscordPTB",         Path.Combine(appData, "discordptb")),
            ("DiscordCanary",      Path.Combine(appData, "discordcanary")),
            ("DiscordDevelopment", Path.Combine(appData, "discorddevelopment")),
        };

        // Dedupe by user ID so the same account showing up in both stable
        // Discord and DiscordPTB doesn't render twice.
        var found = new Dictionary<string, DiscordAccount>(StringComparer.Ordinal);
        var perVariantStats = new List<(string Variant, int Files, long Bytes, bool Existed)>();

        foreach (var (variant, appRoot) in variants)
        {
            if (!Directory.Exists(appRoot))
            {
                continue;
            }

            int files = 0;
            long bytes = 0;
            bool anyDirExisted = false;

            foreach (var dir in CandidateDirs(appRoot))
            {
                if (!Directory.Exists(dir)) continue;
                anyDirExisted = true;

                foreach (var file in EnumerateScannableFiles(dir))
                {
                    byte[] data;
                    try
                    {
                        data = ReadUpTo(file, PerFileByteBudget);
                    }
                    catch (Exception ex)
                    {
                        ConsoleUI.Dim($"  (could not read {file}: {ex.Message})");
                        continue;
                    }
                    if (data.Length == 0) continue;
                    files++;
                    bytes += data.Length;

                    var asUtf8  = SafeDecode(data, Encoding.UTF8);
                    var asUtf16 = SafeDecode(data, Encoding.Unicode);

                    foreach (var text in new[] { asUtf8, asUtf16 })
                        ExtractAccounts(text, variant, found);
                }
            }

            perVariantStats.Add((variant, files, bytes, anyDirExisted));
        }

        // Emit per-scan summary so the user can tell why "0 accounts" was
        // returned (e.g. nothing scanned at all vs. lots of files but no
        // matches).
        var anyFiles    = perVariantStats.Sum(p => p.Files);
        var anyVariants = perVariantStats.Count(p => p.Existed);

        if (anyFiles == 0 && anyVariants == 0)
        {
            ConsoleUI.Ok("No Discord local-storage to scan (Discord may not be installed).");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Ok,
                Title: "Discord client not installed",
                Detail: $"Looked under: {string.Join(", ", variants.Select(v => v.AppRoot))}",
                Tags: new[] { "discord", "scan-summary" }));
            return;
        }

        var summary = string.Join("\n", perVariantStats
            .Where(p => p.Existed)
            .Select(p => $"  - {p.Variant}: {p.Files} file(s), {p.Bytes / 1024} KiB"));

        if (found.Count == 0)
        {
            ConsoleUI.Ok($"No signed-in Discord accounts found ({anyFiles} storage file(s) scanned).");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Info,
                Title: "Discord scan: no signed-in account snowflake found",
                Detail: "Scanned Local Storage, Session Storage, and IndexedDB for "
                      + "remoteAuth / multi-account / inline user objects. The "
                      + "client may not be signed in, or the local cache may have "
                      + "been wiped. Per-variant summary:\n" + summary,
                Tags: new[] { "discord", "scan-summary" }));
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
    /// All Chromium storage subdirectories where Discord may keep account
    /// data. Discord has been moving fields between these over the years,
    /// so we scan all of them.
    /// </summary>
    private static IEnumerable<string> CandidateDirs(string appRoot)
    {
        yield return Path.Combine(appRoot, "Local Storage", "leveldb");
        yield return Path.Combine(appRoot, "Session Storage");
        yield return Path.Combine(appRoot, "IndexedDB");
    }

    /// <summary>
    /// Enumerate every leveldb-style file inside <paramref name="root"/>
    /// (recursively for IndexedDB which has per-origin subfolders). We
    /// scan <c>.log</c> + <c>.ldb</c> + the manifest. .ldb is
    /// snappy-framed but JSON literals usually survive the framing.
    /// </summary>
    private static IEnumerable<string> EnumerateScannableFiles(string root)
    {
        IEnumerable<string> walk(string pattern, SearchOption opt)
        {
            try { return Directory.EnumerateFiles(root, pattern, opt); }
            catch { return Array.Empty<string>(); }
        }
        // Local Storage / Session Storage are flat. IndexedDB has
        // per-origin subdirs (https_discord.com_0.indexeddb.leveldb/,
        // https_discordapp.com_0.indexeddb.leveldb/). Walk recursively.
        var opt = SearchOption.AllDirectories;
        foreach (var f in walk("*.log", opt))      yield return f;
        foreach (var f in walk("*.ldb", opt))      yield return f;
        foreach (var f in walk("MANIFEST-*", opt)) yield return f;
    }

    /// <summary>Read at most <paramref name="max"/> bytes from a file (FileShare.ReadWrite).</summary>
    private static byte[] ReadUpTo(string path, int max)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var buf = new byte[81920];
        using var ms = new MemoryStream();
        int total = 0;
        while (total < max)
        {
            int want = Math.Min(buf.Length, max - total);
            int n = fs.Read(buf, 0, want);
            if (n <= 0) break;
            ms.Write(buf, 0, n);
            total += n;
        }
        return ms.ToArray();
    }

    /// <summary>
    /// Decode bytes as <paramref name="enc"/>, replacing any malformed
    /// sequences. The decoder error fallback keeps the regex working — we
    /// never throw on a bad codepoint.
    /// </summary>
    private static string SafeDecode(byte[] data, Encoding enc)
    {
        try
        {
            var clone = (Encoding)enc.Clone();
            clone.DecoderFallback = DecoderFallback.ReplacementFallback;
            return clone.GetString(data);
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>Run all our extraction strategies against a single text blob.</summary>
    private static void ExtractAccounts(
        string text, string variant, Dictionary<string, DiscordAccount> found)
    {
        if (string.IsNullOrEmpty(text)) return;

        // Strategy 1 — _remoteAuth_recentAccounts: array of
        // {"userId":"…","name":"…","avatarHash":"…"} entries written when
        // the user signs in via QR / phone hand-off.
        foreach (Match m in RemoteAuthAccount.Matches(text))
        {
            var id = m.Groups["id"].Value;
            if (!IsSnowflake(id)) continue;
            var name = Unescape(m.Groups["name"].Value);
            if (!found.ContainsKey(id))
            {
                found[id] = new DiscordAccount(
                    UserId: id,
                    Username: name,
                    AvatarHash: m.Groups["avatar"].Success && m.Groups["avatar"].Value.Length > 0
                                  ? m.Groups["avatar"].Value : null,
                    ClientVariant: variant);
            }
        }

        // Strategy 2 — inline user objects in the redux state cache:
        // {"id":"…","username":"…",…,"global_name":"Foo",…,"avatar":"abc"}
        foreach (Match m in InlineUserObject.Matches(text))
        {
            var id = m.Groups["id"].Value;
            if (!IsSnowflake(id)) continue;
            var username = Unescape(m.Groups["username"].Value);
            if (string.IsNullOrEmpty(username)) continue;
            MergeAccount(found, id, username,
                global: m.Groups["global"].Success && m.Groups["global"].Value.Length > 0
                          ? Unescape(m.Groups["global"].Value) : null,
                avatar: m.Groups["avatar"].Success && m.Groups["avatar"].Value.Length > 0
                          ? m.Groups["avatar"].Value : null,
                variant: variant);
        }

        // Strategy 3 — MULTI_ACCOUNT_STORE: Discord persists the active
        // user id + a redacted user object here. Pattern allows username
        // + avatar to appear in any order around the snowflake.
        foreach (Match m in MultiAccountStore.Matches(text))
        {
            var id = m.Groups["id"].Value;
            if (!IsSnowflake(id)) continue;
            var username = m.Groups["username"].Success
                ? Unescape(m.Groups["username"].Value) : id;
            MergeAccount(found, id, username,
                global: null,
                avatar: m.Groups["avatar"].Success && m.Groups["avatar"].Value.Length > 0
                          ? m.Groups["avatar"].Value : null,
                variant: variant);
        }
    }

    private static void MergeAccount(
        Dictionary<string, DiscordAccount> found,
        string id, string username, string? global, string? avatar, string variant)
    {
        if (!found.TryGetValue(id, out var existing))
        {
            found[id] = new DiscordAccount(
                UserId: id, Username: username,
                GlobalName: global, AvatarHash: avatar, ClientVariant: variant);
            return;
        }

        // Backfill any field the prior strategy didn't have.
        var merged = existing;
        if (string.IsNullOrEmpty(existing.Username) && !string.IsNullOrEmpty(username))
            merged = merged with { Username = username };
        if (existing.GlobalName == null && global != null)
            merged = merged with { GlobalName = global };
        if (existing.AvatarHash == null && avatar != null)
            merged = merged with { AvatarHash = avatar };
        found[id] = merged;
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

    // MULTI_ACCOUNT_STORE entries — the actual key in localStorage is
    // "MultiAccountStore" / "_multi_account_store", and Discord serialises
    // the per-id user record as a JSON object next to it.
    private static readonly Regex MultiAccountStore = new(
        @"MultiAccountStore[^{}]{0,500}?""id""\s*:\s*""(?<id>\d{17,20})""(?:[^{}]{0,200}?""username""\s*:\s*""(?<username>(?:\\""|[^""])*)"")?(?:[^{}]{0,200}?""avatar""\s*:\s*""(?<avatar>[a-fA-F0-9_]+)?"")?",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
}
