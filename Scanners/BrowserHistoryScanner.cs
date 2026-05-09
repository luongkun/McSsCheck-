using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using Microsoft.Data.Sqlite;
using McSsCheck.Data;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

[SupportedOSPlatform("windows")]
internal static class BrowserHistoryScanner
{
    public const string SourceName = "BrowserHistoryScanner";

    /// <summary>
    /// One row from any browser's history that matched a cheat-domain
    /// keyword. We collect every match across every browser / profile
    /// before emitting a single aggregated finding sorted newest-first.
    /// </summary>
    private sealed record HistHit(
        DateTime VisitedUtc,
        string   Url,
        string   Title,
        string   Browser,
        string   ProfileLabel,
        string[] MatchedKeywords,
        string   HistoryDb);

    public static void Run(SessionReport.Section section)
    {
        ConsoleUI.Section("Browser history (cheat-client domains only)");

        // v0.9.2: collapse per-URL findings into a single, sorted card.
        // Staff complained that v0.9.1 reports had ~14 separate
        // "Cheat-client domain in browser history" cards for one player —
        // now it's one card with a chronological list inside.
        var hits = new List<HistHit>();
        ScanChromiumLikeHistory(section, hits);
        ScanFirefoxHistory(section, hits);

        if (hits.Count == 0) return;

        // Newest-first.
        hits.Sort((a, b) => b.VisitedUtc.CompareTo(a.VisitedUtc));

        var distinctKeywords = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in hits)
            foreach (var kw in h.MatchedKeywords) distinctKeywords.Add(kw);

        const int MaxRows = 25;
        var lines = new List<string>();
        for (int i = 0; i < hits.Count && i < MaxRows; i++)
        {
            var h = hits[i];
            var ts = h.VisitedUtc == DateTime.MinValue
                ? "(no timestamp)"
                : h.VisitedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm");
            var label = string.IsNullOrEmpty(h.ProfileLabel) ? h.Browser : $"{h.Browser} / {h.ProfileLabel}";
            var titlePart = string.IsNullOrEmpty(h.Title) ? "" : $"  {h.Title}";
            lines.Add($"{ts}  [{label}]  {h.Url}  -> {string.Join(", ", h.MatchedKeywords)}{titlePart}");
        }
        if (hits.Count > MaxRows) lines.Add($"... and {hits.Count - MaxRows} more older visit(s)");

        // Use the most-recent history DB as FilePath so the report card
        // can still link to *one* on-disk source. Keywords union becomes
        // the tag list so cross-source dedup works the same as before.
        var representativeDb = hits[0].HistoryDb;
        var detail = $"{hits.Count} cheat-client visit(s) across browsers, sorted newest first:\n  "
                   + string.Join("\n  ", lines);

        section.Add(new ScanResult(
            Source: SourceName, Severity: Severity.Hit,
            Title: hits.Count == 1
                ? "Cheat-client domain in browser history"
                : $"Cheat-client domains in browser history ({hits.Count})",
            Detail: detail,
            FilePath: representativeDb,
            Tags: distinctKeywords.ToArray()));
    }

    private static void ScanChromiumLikeHistory(SessionReport.Section section, List<HistHit> hits)
    {
        var localAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var browserBases = new (string Path, string Label)[]
        {
            (Path.Combine(localAppdata, "Google",  "Chrome",         "User Data"), "Chrome"),
            (Path.Combine(localAppdata, "Microsoft","Edge",            "User Data"), "Edge"),
            (Path.Combine(localAppdata, "BraveSoftware","Brave-Browser","User Data"), "Brave"),
            (Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Opera Software", "Opera Stable"), "Opera"),
            (Path.Combine(localAppdata, "Vivaldi", "User Data"), "Vivaldi"),
        };

        foreach (var (basePath, label) in browserBases)
        {
            if (!Directory.Exists(basePath)) continue;

            // Chromium browsers: a single "History" file in basePath OR per-profile
            // subdirectories ("Default", "Profile 1", ...) each containing one.
            IEnumerable<(string Db, string Profile)> histDbs;
            var rootDb = Path.Combine(basePath, "History");
            if (File.Exists(rootDb))
            {
                histDbs = new[] { (rootDb, "") };
            }
            else
            {
                histDbs = Directory.EnumerateDirectories(basePath)
                    .Select(d => (Db: Path.Combine(d, "History"), Profile: Path.GetFileName(d)))
                    .Where(t => File.Exists(t.Db));
            }

            foreach (var (db, profile) in histDbs)
                ScanChromiumDb(label, profile, db, section, hits);
        }
    }

    private static void ScanChromiumDb(
        string browserLabel, string profileLabel,
        string historyDb, SessionReport.Section section, List<HistHit> hits)
    {
        string tmp;
        try
        {
            tmp = Path.Combine(Path.GetTempPath(), $"mcss-{Guid.NewGuid():N}.sqlite");
            File.Copy(historyDb, tmp, overwrite: true);
        }
        catch (Exception ex)
        {
            ConsoleUI.Warn($"  cannot copy {historyDb} ({ex.Message}). Close the browser and re-run.");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Warn,
                Title: "Browser history DB locked",
                Detail: $"{historyDb}: {ex.Message}", FilePath: historyDb));
            return;
        }

        try
        {
            using var conn = new SqliteConnection($"Data Source={tmp};Mode=ReadOnly;Cache=Shared");
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC";
            using var rdr = cmd.ExecuteReader();

            int matched = 0;
            while (rdr.Read())
            {
                var url = rdr.GetString(0);
                var title = rdr.IsDBNull(1) ? "" : rdr.GetString(1);
                var keywords = KnownCheats.MatchKeywords(url, KnownCheats.CheatDomains).ToList();
                if (keywords.Count == 0) continue;

                long ticks = rdr.IsDBNull(2) ? 0 : rdr.GetInt64(2);
                var visited = ChromiumTimeToDateTime(ticks);

                hits.Add(new HistHit(
                    VisitedUtc: visited,
                    Url: url,
                    Title: title,
                    Browser: browserLabel,
                    ProfileLabel: profileLabel,
                    MatchedKeywords: keywords.ToArray(),
                    HistoryDb: historyDb));
                matched++;
                ConsoleUI.Hit($"  {browserLabel}/{profileLabel}: domain hits [{string.Join(",", keywords)}]: {url}  ({title})");
            }
            if (matched == 0)
                ConsoleUI.Ok($"{browserLabel}/{profileLabel}: no cheat-client domains in history.");
        }
        catch (Exception ex)
        {
            ConsoleUI.Warn($"  cannot query {historyDb}: {ex.Message}");
        }
        finally
        {
            try { File.Delete(tmp); } catch { /* best effort */ }
        }
    }

    private static void ScanFirefoxHistory(SessionReport.Section section, List<HistHit> hits)
    {
        var ffRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Mozilla", "Firefox", "Profiles");
        if (!Directory.Exists(ffRoot)) return;

        foreach (var profile in Directory.EnumerateDirectories(ffRoot))
        {
            var places = Path.Combine(profile, "places.sqlite");
            if (!File.Exists(places)) continue;

            string tmp;
            try
            {
                tmp = Path.Combine(Path.GetTempPath(), $"mcss-ff-{Guid.NewGuid():N}.sqlite");
                File.Copy(places, tmp, overwrite: true);
            }
            catch (Exception ex)
            {
                ConsoleUI.Warn($"  cannot copy {places} ({ex.Message}). Close Firefox and re-run.");
                continue;
            }

            try
            {
                using var conn = new SqliteConnection($"Data Source={tmp};Mode=ReadOnly;Cache=Shared");
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT url, title, last_visit_date FROM moz_places ORDER BY last_visit_date DESC";
                using var rdr = cmd.ExecuteReader();

                int matched = 0;
                while (rdr.Read())
                {
                    var url = rdr.GetString(0);
                    var title = rdr.IsDBNull(1) ? "" : rdr.GetString(1);
                    var keywords = KnownCheats.MatchKeywords(url, KnownCheats.CheatDomains).ToList();
                    if (keywords.Count == 0) continue;

                    long ticks = rdr.IsDBNull(2) ? 0 : rdr.GetInt64(2);
                    var visited = FirefoxTimeToDateTime(ticks);

                    hits.Add(new HistHit(
                        VisitedUtc: visited,
                        Url: url,
                        Title: title,
                        Browser: "Firefox",
                        ProfileLabel: Path.GetFileName(profile),
                        MatchedKeywords: keywords.ToArray(),
                        HistoryDb: places));
                    matched++;
                    ConsoleUI.Hit($"  Firefox/{Path.GetFileName(profile)}: domain hits [{string.Join(",", keywords)}]: {url}  ({title})");
                }
                if (matched == 0)
                    ConsoleUI.Ok($"Firefox profile {Path.GetFileName(profile)}: no cheat-client domains.");
            }
            catch (Exception ex)
            {
                ConsoleUI.Warn($"  cannot query {places}: {ex.Message}");
            }
            finally
            {
                try { File.Delete(tmp); } catch { /* best effort */ }
            }
        }
    }

    /// <summary>Chromium stores last_visit_time as microseconds since 1601-01-01 (Webkit/FILETIME).</summary>
    private static DateTime ChromiumTimeToDateTime(long ticks)
    {
        if (ticks <= 0) return DateTime.MinValue;
        try
        {
            var epoch = new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            return epoch.AddTicks(ticks * 10);
        }
        catch { return DateTime.MinValue; }
    }

    /// <summary>Firefox stores last_visit_date as microseconds since 1970-01-01 (Unix * 1e6).</summary>
    private static DateTime FirefoxTimeToDateTime(long ticks)
    {
        if (ticks <= 0) return DateTime.MinValue;
        try
        {
            return DateTimeOffset.FromUnixTimeMilliseconds(ticks / 1000).UtcDateTime;
        }
        catch { return DateTime.MinValue; }
    }
}
