using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using McSsCheck.Models;
using McSsCheck.Scanners;

namespace McSsCheck.Util;

/// <summary>
/// Optional VirusTotal v3 lookup for SHA-256 hashes that <see cref="MinecraftScanner"/>
/// has already computed. The user must supply their own API key (env <c>VT_API_KEY</c>
/// or <c>--vt-key</c> CLI flag); without it this module no-ops.
///
/// All requests go to the public <c>https://www.virustotal.com/api/v3/files/{hash}</c>
/// endpoint and only ever submit the hash — never the file. Free-tier API keys are
/// limited to 4 req/min and 500 req/day, so we throttle to ~1 req every 16 seconds
/// and cap total lookups per session at 24.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class VirusTotalChecker
{
    public const string SourceName = "VirusTotalChecker";

    private const int MaxLookupsPerSession = 24;
    private static readonly TimeSpan MinDelayBetweenCalls = TimeSpan.FromSeconds(16);

    public static async Task RunAsync(SessionReport.Section section, string? apiKey, CancellationToken ct = default)
    {
        ConsoleUI.Section("VirusTotal hash lookups (optional)");

        if (string.IsNullOrWhiteSpace(apiKey))
        {
            ConsoleUI.Dim("No VT_API_KEY / --vt-key supplied — skipping VirusTotal step.");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Info,
                Title: "VirusTotal lookups skipped",
                Detail: "Provide --vt-key <key> or set VT_API_KEY env var to enable. Only SHA-256 hashes are sent — never file contents."));
            return;
        }

        var hashes = MinecraftScanner.JarHashes
            .GroupBy(kv => kv.Value.Sha256, StringComparer.OrdinalIgnoreCase)
            .Select(g => (Sha256: g.Key, Paths: g.Select(x => x.Key).ToList()))
            .Take(MaxLookupsPerSession)
            .ToList();

        if (hashes.Count == 0)
        {
            ConsoleUI.Ok("No jar hashes to look up.");
            return;
        }

        ConsoleUI.Info($"Looking up {hashes.Count} hash(es) on VirusTotal (rate-limited; ~{hashes.Count * 16}s)...");

        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        http.DefaultRequestHeaders.UserAgent.ParseAdd("McSsCheck/0.2.0 (+local)");
        http.DefaultRequestHeaders.Add("x-apikey", apiKey);

        var first = true;
        foreach (var (sha, paths) in hashes)
        {
            if (ct.IsCancellationRequested) break;
            if (!first)
            {
                try { await Task.Delay(MinDelayBetweenCalls, ct); } catch { break; }
            }
            first = false;

            await LookupOneAsync(http, sha, paths, section, ct);
        }
    }

    private static async Task LookupOneAsync(HttpClient http, string sha, List<string> paths,
                                             SessionReport.Section section, CancellationToken ct)
    {
        var url = $"https://www.virustotal.com/api/v3/files/{sha}";
        try
        {
            using var resp = await http.GetAsync(url, ct);
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                ConsoleUI.Dim($"  VT: unknown hash {sha[..12]}…  ({paths[0]})");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Info,
                    Title: $"VT: hash unknown ({sha[..12]}…)",
                    Detail: string.Join("\n", paths),
                    Hash: sha, FilePath: paths[0]));
                return;
            }
            if (resp.StatusCode == System.Net.HttpStatusCode.Unauthorized ||
                resp.StatusCode == System.Net.HttpStatusCode.Forbidden)
            {
                ConsoleUI.Warn($"  VT: API key rejected ({(int)resp.StatusCode}). Aborting VT step.");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Warn,
                    Title: "VT: API key rejected",
                    Detail: $"HTTP {(int)resp.StatusCode}"));
                throw new OperationCanceledException();
            }
            if (resp.StatusCode == (System.Net.HttpStatusCode)429)
            {
                ConsoleUI.Warn("  VT: rate-limited (HTTP 429). Skipping the rest.");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Warn,
                    Title: "VT: rate-limited (HTTP 429)",
                    Detail: "Free-tier API key reached its quota."));
                throw new OperationCanceledException();
            }

            resp.EnsureSuccessStatusCode();
            var json = await resp.Content.ReadAsStringAsync(ct);

            using var doc = JsonDocument.Parse(json);
            var stats = doc.RootElement
                .GetProperty("data").GetProperty("attributes").GetProperty("last_analysis_stats");
            int malicious   = stats.TryGetProperty("malicious",   out var m) ? m.GetInt32() : 0;
            int suspicious  = stats.TryGetProperty("suspicious",  out var s) ? s.GetInt32() : 0;
            int undetected  = stats.TryGetProperty("undetected",  out var u) ? u.GetInt32() : 0;
            int harmless    = stats.TryGetProperty("harmless",    out var h) ? h.GetInt32() : 0;

            string permalink = $"https://www.virustotal.com/gui/file/{sha}";
            string headline = $"VT: malicious={malicious}, suspicious={suspicious}, undetected={undetected}, harmless={harmless}";

            if (malicious > 0)
            {
                ConsoleUI.Hit($"  VT HIT [{malicious} engines flagged]: {sha[..12]}…  ({paths[0]})");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Hit,
                    Title: $"VirusTotal: {malicious} engines flagged this jar",
                    Detail: $"{headline}\n{permalink}\n\nfiles:\n  - {string.Join("\n  - ", paths)}",
                    Hash: sha, FilePath: paths[0],
                    Tags: new[] { "virustotal" }));
            }
            else if (suspicious > 0)
            {
                ConsoleUI.Warn($"  VT suspicious [{suspicious}]: {sha[..12]}…  ({paths[0]})");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Warn,
                    Title: $"VirusTotal: {suspicious} engines flagged jar as suspicious",
                    Detail: $"{headline}\n{permalink}\n\nfiles:\n  - {string.Join("\n  - ", paths)}",
                    Hash: sha, FilePath: paths[0],
                    Tags: new[] { "virustotal" }));
            }
            else
            {
                ConsoleUI.Ok($"  VT clean: {sha[..12]}… ({headline})");
                section.Add(new ScanResult(
                    Source: SourceName, Severity: Severity.Ok,
                    Title: "VirusTotal: clean",
                    Detail: $"{headline}\n{permalink}\nfile: {paths[0]}",
                    Hash: sha, FilePath: paths[0]));
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            ConsoleUI.Warn($"  VT lookup failed for {sha[..12]}…: {ex.Message}");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Error,
                Title: "VT lookup failed",
                Detail: ex.Message,
                Hash: sha, FilePath: paths[0]));
        }
    }
}
