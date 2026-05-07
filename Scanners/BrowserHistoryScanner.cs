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

    public static void Run(SessionReport.Section section)
    {
        ConsoleUI.Section("Browser history (cheat-client domains only)");
        ScanChromiumLikeHistory(section);
        ScanFirefoxHistory(section);
    }

    private static void ScanChromiumLikeHistory(SessionReport.Section section)
    {
        var localAppdata = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        var browserBases = new[]
        {
            Path.Combine(localAppdata, "Google",  "Chrome",         "User Data"),
            Path.Combine(localAppdata, "Microsoft","Edge",            "User Data"),
            Path.Combine(localAppdata, "BraveSoftware","Brave-Browser","User Data"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Opera Software", "Opera Stable"),
            Path.Combine(localAppdata, "Vivaldi", "User Data"),
        };

        foreach (var basePath in browserBases)
        {
            if (!Directory.Exists(basePath)) continue;

            IEnumerable<string> histDbs;
            if (File.Exists(Path.Combine(basePath, "History")))
                histDbs = new[] { Path.Combine(basePath, "History") };
            else
                histDbs = Directory.EnumerateDirectories(basePath)
                    .Select(d => Path.Combine(d, "History"))
                    .Where(File.Exists);

            foreach (var db in histDbs)
                ScanChromiumDb(basePath, db, section);
        }
    }

    private static void ScanChromiumDb(string browserBase, string historyDb, SessionReport.Section section)
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

            int hits = 0;
            while (rdr.Read())
            {
                var url = rdr.GetString(0);
                var title = rdr.IsDBNull(1) ? "" : rdr.GetString(1);
                var matched = KnownCheats.MatchKeywords(url, KnownCheats.CheatDomains).ToList();
                if (matched.Count == 0) continue;

                hits++;
                ConsoleUI.Hit($"  {browserBase}: domain hits [{string.Join(",", matched)}]: {url}  ({title})");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Hit,
                    Title: "Cheat-client domain in browser history",
                    Detail: $"{browserBase}\nurl={url}\ntitle={title}\nmatched: {string.Join(", ", matched)}",
                    FilePath: historyDb, Tags: matched.ToArray()));
            }
            if (hits == 0) ConsoleUI.Ok($"{browserBase}: no cheat-client domains in history.");
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

    private static void ScanFirefoxHistory(SessionReport.Section section)
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

                int hits = 0;
                while (rdr.Read())
                {
                    var url = rdr.GetString(0);
                    var title = rdr.IsDBNull(1) ? "" : rdr.GetString(1);
                    var matched = KnownCheats.MatchKeywords(url, KnownCheats.CheatDomains).ToList();
                    if (matched.Count == 0) continue;

                    hits++;
                    ConsoleUI.Hit($"  Firefox {Path.GetFileName(profile)}: domain hits [{string.Join(",", matched)}]: {url}  ({title})");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Hit,
                        Title: "Cheat-client domain in Firefox history",
                        Detail: $"profile={Path.GetFileName(profile)}\nurl={url}\ntitle={title}\nmatched: {string.Join(", ", matched)}",
                        FilePath: places, Tags: matched.ToArray()));
                }
                if (hits == 0) ConsoleUI.Ok($"Firefox profile {Path.GetFileName(profile)}: no cheat-client domains.");
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
}
