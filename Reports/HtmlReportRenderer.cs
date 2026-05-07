using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Versioning;
using System.Text;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Reports;

[SupportedOSPlatform("windows")]
internal static class HtmlReportRenderer
{
    /// <summary>Renders <paramref name="report"/> to <paramref name="outputPath"/> and returns the path written.</summary>
    public static string RenderToFile(SessionReport report, string? outputPath = null)
    {
        outputPath ??= Path.Combine(Path.GetTempPath(),
            $"mcss-report-{DateTime.Now:yyyyMMdd-HHmmss}.html");

        File.WriteAllText(outputPath, Render(report), new UTF8Encoding(false));
        return outputPath;
    }

    public static void OpenInBrowser(string filePath)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName        = filePath,
                UseShellExecute = true,
            };
            Process.Start(psi);
        }
        catch (Exception ex)
        {
            ConsoleUI.Warn($"Could not open report in browser: {ex.Message}");
            ConsoleUI.Info($"Open manually: {filePath}");
        }
    }

    private static string Render(SessionReport r)
    {
        var hits  = r.Sections.Sum(s => s.Hits);
        var warns = r.Sections.Sum(s => s.Warnings);
        var infos = r.Sections.Sum(s => s.Results.Count(x => x.Severity == Severity.Info));
        var oks   = r.Sections.Sum(s => s.Results.Count(x => x.Severity == Severity.Ok));
        var errs  = r.Sections.Sum(s => s.Results.Count(x => x.Severity == Severity.Error));

        var verdictClass = hits > 0 ? "verdict-hit" : warns > 0 ? "verdict-warn" : "verdict-clean";
        var verdictText  = hits > 0
            ? $"{hits} hit(s) — review each one"
            : warns > 0 ? $"{warns} warning(s)" : "No hits";

        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang='en'>");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset='utf-8'>");
        sb.AppendLine($"  <title>McSsCheck report — {Esc(r.Hostname)} — {r.StartedAt:yyyy-MM-dd HH:mm}</title>");
        sb.AppendLine("  <style>");
        sb.Append(Css());
        sb.AppendLine("  </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");

        sb.AppendLine($"<header class='top'>");
        sb.AppendLine($"  <h1>McSsCheck report</h1>");
        sb.AppendLine($"  <div class='meta'>");
        sb.AppendLine($"    <span><b>Host:</b> {Esc(r.Hostname)}</span>");
        sb.AppendLine($"    <span><b>User:</b> {Esc(r.Username)}</span>");
        sb.AppendLine($"    <span><b>OS:</b> {Esc(r.OsVersion)}</span>");
        sb.AppendLine($"    <span><b>Started:</b> {r.StartedAt:yyyy-MM-dd HH:mm:ss}</span>");
        sb.AppendLine($"    <span><b>Finished:</b> {r.FinishedAt?.ToString("yyyy-MM-dd HH:mm:ss") ?? "-"}</span>");
        sb.AppendLine($"    <span><b>Tool:</b> v{Esc(r.ToolVersion)}</span>");
        sb.AppendLine($"  </div>");
        sb.AppendLine($"  <div class='verdict {verdictClass}'>{Esc(verdictText)}</div>");
        sb.AppendLine($"  <div class='counts'>");
        sb.AppendLine($"    <span class='c-hit'>HIT {hits}</span>");
        sb.AppendLine($"    <span class='c-warn'>WARN {warns}</span>");
        sb.AppendLine($"    <span class='c-info'>INFO {infos}</span>");
        sb.AppendLine($"    <span class='c-ok'>OK {oks}</span>");
        sb.AppendLine($"    <span class='c-err'>ERR {errs}</span>");
        sb.AppendLine($"  </div>");
        sb.AppendLine($"  <p class='disclaimer'>This is a triage report. Each <b>HIT</b> is a candidate for manual review by staff during the screenshare; it is not a guilty verdict on its own.</p>");
        sb.AppendLine("</header>");

        // Table of contents
        sb.AppendLine("<nav class='toc'>");
        sb.AppendLine("<h2>Sections</h2>");
        sb.AppendLine("<ol>");
        for (int i = 0; i < r.Sections.Count; i++)
        {
            var s = r.Sections[i];
            sb.AppendLine($"  <li><a href='#sec-{i}'>{Esc(s.Title)}</a> " +
                          $"<span class='c-hit'>{s.Hits}</span> " +
                          $"<span class='c-warn'>{s.Warnings}</span></li>");
        }
        sb.AppendLine("</ol>");
        sb.AppendLine("</nav>");

        // Sections
        for (int i = 0; i < r.Sections.Count; i++)
        {
            var s = r.Sections[i];
            sb.AppendLine($"<section id='sec-{i}' class='sec'>");
            sb.AppendLine($"  <h2>{Esc(s.Title)} <small>({s.Results.Count} entries · {s.Hits} hit · {s.Warnings} warn)</small></h2>");
            if (s.Results.Count == 0)
            {
                sb.AppendLine("  <p class='empty'>(no findings)</p>");
            }
            else
            {
                sb.AppendLine("  <table>");
                sb.AppendLine("    <thead><tr><th>sev</th><th>title</th><th>file / detail</th><th>tags</th><th>time</th></tr></thead>");
                sb.AppendLine("    <tbody>");
                foreach (var entry in s.Results)
                {
                    var sev = entry.Severity.ToString().ToLowerInvariant();
                    sb.AppendLine($"    <tr class='row-{sev}'>");
                    sb.AppendLine($"      <td><span class='sev-{sev}'>{sev.ToUpperInvariant()}</span></td>");
                    sb.AppendLine($"      <td>{Esc(entry.Title)}</td>");
                    sb.AppendLine("      <td>");
                    if (!string.IsNullOrEmpty(entry.FilePath))
                        sb.AppendLine($"        <code class='path'>{Esc(entry.FilePath)}</code>");
                    if (!string.IsNullOrEmpty(entry.Hash))
                        sb.AppendLine($"        <div class='hash'>sha256: {Esc(entry.Hash)}</div>");
                    if (!string.IsNullOrEmpty(entry.Detail))
                        sb.AppendLine($"        <pre class='detail'>{Esc(entry.Detail)}</pre>");
                    sb.AppendLine("      </td>");
                    sb.AppendLine("      <td>");
                    if (entry.Tags is { Count: > 0 })
                        foreach (var t in entry.Tags)
                            sb.Append($"<span class='tag'>{Esc(t)}</span> ");
                    sb.AppendLine("      </td>");
                    sb.AppendLine($"      <td class='ts'>{(entry.Timestamp.HasValue ? entry.Timestamp.Value.ToString("yyyy-MM-dd HH:mm") : "")}</td>");
                    sb.AppendLine($"    </tr>");
                }
                sb.AppendLine("    </tbody>");
                sb.AppendLine("  </table>");
            }
            sb.AppendLine("</section>");
        }

        sb.AppendLine("<footer><small>Generated by McSsCheck v" + Esc(r.ToolVersion)
                      + " — local-only, no network exfiltration.</small></footer>");
        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    private static string Esc(string? s) => s == null ? "" : WebUtility.HtmlEncode(s);

    private static string Css() => @"
:root { color-scheme: light dark; }
body { font: 14px/1.4 -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0; background: #0e1116; color: #e6e6e6; }
header.top { padding: 24px 32px; background: linear-gradient(180deg, #1a1f2b, #0e1116); border-bottom: 1px solid #2a313e; }
header.top h1 { margin: 0 0 8px 0; font-size: 24px; }
.meta { display: flex; flex-wrap: wrap; gap: 12px 24px; font-size: 13px; color: #aaa; }
.meta span b { color: #ddd; font-weight: 600; }
.verdict { display: inline-block; margin-top: 14px; padding: 8px 16px; border-radius: 6px; font-weight: 700; font-size: 16px; }
.verdict-clean { background: #1d3823; color: #b3f0c1; }
.verdict-warn  { background: #3a341a; color: #f5d97c; }
.verdict-hit   { background: #4a1c1c; color: #ffb3b3; }
.counts { margin-top: 12px; display: flex; gap: 8px; }
.counts span { padding: 3px 10px; border-radius: 4px; font-size: 12px; font-family: ui-monospace, monospace; }
.c-hit  { background: #4a1c1c; color: #ffb3b3; }
.c-warn { background: #3a341a; color: #f5d97c; }
.c-info { background: #1a2a3e; color: #a3c4e6; }
.c-ok   { background: #1d3823; color: #b3f0c1; }
.c-err  { background: #2a2a2a; color: #ddd; }
.disclaimer { margin-top: 12px; color: #aaa; font-size: 12px; }
nav.toc { padding: 16px 32px; background: #131820; border-bottom: 1px solid #2a313e; }
nav.toc h2 { margin: 0 0 8px 0; font-size: 14px; color: #aaa; text-transform: uppercase; letter-spacing: 1px; }
nav.toc ol { margin: 0; padding-left: 24px; }
nav.toc a { color: #6cb6ff; text-decoration: none; }
nav.toc a:hover { text-decoration: underline; }
section.sec { padding: 20px 32px; border-bottom: 1px solid #1f2630; }
section.sec h2 { margin: 0 0 12px 0; font-size: 18px; }
section.sec h2 small { color: #888; font-weight: normal; font-size: 13px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; vertical-align: top; padding: 8px 10px; border-bottom: 1px solid #232a36; }
th { color: #888; font-size: 12px; text-transform: uppercase; font-weight: 600; letter-spacing: 0.5px; }
tr.row-hit  { background: rgba(255, 80, 80, 0.07); }
tr.row-warn { background: rgba(245, 217, 124, 0.04); }
.sev-hit  { color: #ffb3b3; font-weight: 700; }
.sev-warn { color: #f5d97c; font-weight: 700; }
.sev-info { color: #a3c4e6; }
.sev-ok   { color: #b3f0c1; }
.sev-err  { color: #ddd; }
code.path { font-family: ui-monospace, monospace; font-size: 12px; background: #1a1f2b; padding: 2px 6px; border-radius: 3px; word-break: break-all; }
.hash { font-family: ui-monospace, monospace; font-size: 11px; color: #aaa; margin-top: 4px; word-break: break-all; }
pre.detail { font-family: ui-monospace, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-word; background: #131820; padding: 6px 8px; border-radius: 4px; margin: 6px 0 0 0; max-width: 60vw; }
.tag { display: inline-block; padding: 1px 6px; border-radius: 3px; background: #2a313e; color: #c0c0c0; font-size: 11px; font-family: ui-monospace, monospace; margin-right: 4px; }
.ts { color: #888; font-family: ui-monospace, monospace; font-size: 12px; white-space: nowrap; }
.empty { color: #888; font-style: italic; }
footer { padding: 16px 32px; color: #666; font-size: 12px; }
@media (prefers-color-scheme: light) {
  body { background: #f7f8fa; color: #222; }
  header.top { background: linear-gradient(180deg, #fff, #f0f2f6); border-bottom-color: #ddd; }
  .meta { color: #555; } .meta span b { color: #222; }
  .disclaimer { color: #555; }
  nav.toc { background: #f0f2f6; border-bottom-color: #ddd; }
  section.sec { border-bottom-color: #e2e6ee; }
  th { color: #666; } th, td { border-bottom-color: #e2e6ee; }
  code.path { background: #eef0f4; }
  pre.detail { background: #eef0f4; }
  .tag { background: #e2e6ee; color: #333; }
}
";
}
