using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using McSsCheck.Models;

namespace McSsCheck.Util;

/// <summary>
/// Verifies <see cref="SessionReport.Mods"/> entries against the public
/// Modrinth API.
///
/// We POST a list of SHA-1 hashes to <c>POST /v2/version_files</c>; for any
/// hash Modrinth recognises, the response includes the project id, version,
/// download URL etc. Hashes Modrinth does NOT recognise are simply absent
/// from the response — those mods are marked <c>NotVerified</c>.
///
/// Modrinth's API is keyless and rate-limited generously (300 req/min). We
/// still cap requests at one batch of up to 200 hashes per session to be
/// polite. This module makes outbound HTTPS calls and is opt-out via
/// <c>--no-modrinth</c>.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class ModrinthChecker
{
    public const string SourceName = "ModrinthChecker";

    private const int MaxHashesPerBatch = 200;
    private const string Endpoint = "https://api.modrinth.com/v2/version_files";

    public static async Task RunAsync(SessionReport report, SessionReport.Section section,
                                      bool enabled, CancellationToken ct = default)
    {
        ConsoleUI.Section("Mods registry verification (Modrinth)");

        if (!enabled)
        {
            ConsoleUI.Dim("Modrinth lookups disabled (--no-modrinth).");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Info,
                Title: "Modrinth lookups disabled",
                Detail: "Disabled via --no-modrinth flag."));
            foreach (var m in report.Mods) m.Verification = ModVerification.Skipped;
            return;
        }

        var mods = report.Mods.Where(m => !string.IsNullOrEmpty(m.Sha1)).Take(MaxHashesPerBatch).ToList();
        if (mods.Count == 0)
        {
            ConsoleUI.Ok("No mod jars to verify.");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Info,
                Title: "Modrinth: nothing to look up",
                Detail: "MinecraftScanner found no mod jars under .minecraft/mods or versions/."));
            return;
        }

        ConsoleUI.Info($"  looking up {mods.Count} jar SHA-1 hash(es) against Modrinth (one batch)…");

        try
        {
            var dict = await PostBatchAsync(mods.Select(m => m.Sha1!).Distinct().ToList(), ct);

            int verified = 0, notVerified = 0;
            foreach (var mod in mods)
            {
                if (dict.TryGetValue(mod.Sha1!, out var info))
                {
                    mod.Verification = ModVerification.Verified;
                    mod.RegistryName = "Modrinth";
                    mod.RegistryTitle = info.ProjectId; // best we can show without a 2nd API call
                    mod.RegistryDownloadUrl = info.DownloadUrl;
                    ConsoleUI.Ok($"  VERIFIED  {mod.FileName}  ({info.ProjectId})");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Ok,
                        Title: $"VERIFIED on Modrinth: {mod.FileName}",
                        Detail: $"project={info.ProjectId} version={info.VersionId}\nurl={info.DownloadUrl}",
                        FilePath: mod.FilePath, Hash: mod.Sha1,
                        Tags: new[] { "modrinth", "verified" }));
                    verified++;
                }
                else
                {
                    mod.Verification = ModVerification.NotVerified;
                    ConsoleUI.Warn($"  NOT VERIFIED  {mod.FileName}");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Warn,
                        Title: $"Not on Modrinth: {mod.FileName}",
                        Detail: "Hash unknown to the public Modrinth registry — could be a private mod, an unreleased build, or a tampered jar.",
                        FilePath: mod.FilePath, Hash: mod.Sha1,
                        Tags: new[] { "modrinth", "not-verified" }));
                    notVerified++;
                }
            }

            ConsoleUI.Info($"  Modrinth verdict: {verified} verified, {notVerified} not verified");
        }
        catch (OperationCanceledException) { /* user cancelled */ }
        catch (Exception ex)
        {
            ConsoleUI.Warn($"  Modrinth lookup failed: {ex.Message}");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Error,
                Title: "Modrinth lookup failed",
                Detail: ex.Message));
            foreach (var m in mods) m.Verification = ModVerification.Unknown;
        }
    }

    private sealed record ModrinthHit(string ProjectId, string VersionId, string? DownloadUrl);

    private static async Task<Dictionary<string, ModrinthHit>> PostBatchAsync(
        List<string> sha1Hashes, CancellationToken ct)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        http.DefaultRequestHeaders.UserAgent.ParseAdd("McSsCheck/0.3.0 (+local screenshare helper)");

        var body = JsonSerializer.Serialize(new
        {
            hashes    = sha1Hashes,
            algorithm = "sha1",
        });

        using var content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");
        using var resp = await http.PostAsync(Endpoint, content, ct);

        if (resp.StatusCode == (HttpStatusCode)429)
            throw new InvalidOperationException("rate-limited (HTTP 429)");
        resp.EnsureSuccessStatusCode();

        var json = await resp.Content.ReadAsStringAsync(ct);
        using var doc = JsonDocument.Parse(json);

        var dict = new Dictionary<string, ModrinthHit>(StringComparer.OrdinalIgnoreCase);
        foreach (var prop in doc.RootElement.EnumerateObject())
        {
            var v = prop.Value;
            string projectId = v.TryGetProperty("project_id", out var pid) ? (pid.GetString() ?? "?") : "?";
            string versionId = v.TryGetProperty("id",         out var vid) ? (vid.GetString() ?? "?") : "?";
            string? dl = null;
            if (v.TryGetProperty("files", out var files) && files.ValueKind == JsonValueKind.Array)
            {
                foreach (var f in files.EnumerateArray())
                {
                    if (f.TryGetProperty("hashes", out var h) &&
                        h.TryGetProperty("sha1", out var s1) &&
                        string.Equals(s1.GetString(), prop.Name, StringComparison.OrdinalIgnoreCase) &&
                        f.TryGetProperty("url", out var url))
                    {
                        dl = url.GetString();
                        break;
                    }
                }
            }
            dict[prop.Name] = new ModrinthHit(projectId, versionId, dl);
        }
        return dict;
    }
}
