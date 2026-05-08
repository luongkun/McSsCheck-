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
        var counts = r.Counts();
        var verdictClass = counts.Detects > 0 ? "verdict-hit"
                          : counts.Warnings > 0 ? "verdict-warn"
                          : "verdict-clean";
        var verdictText  = counts.Detects > 0
            ? $"{counts.Detects} detect(s) — review each one"
            : counts.Warnings > 0 ? $"{counts.Warnings} warning(s)" : "No detects";

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

        // ----- header / verdict -----
        sb.AppendLine($"<header class='top'>");
        sb.AppendLine($"  <h1>McSsCheck report</h1>");
        sb.AppendLine($"  <div class='meta'>");
        sb.AppendLine($"    <span><b>Host:</b> {Esc(r.Hostname)}</span>");
        sb.AppendLine($"    <span><b>User:</b> {Esc(r.Username)}</span>");
        sb.AppendLine($"    <span><b>Started:</b> {r.StartedAt:yyyy-MM-dd HH:mm:ss}</span>");
        sb.AppendLine($"    <span><b>Finished:</b> {r.FinishedAt?.ToString("yyyy-MM-dd HH:mm:ss") ?? "-"}</span>");
        sb.AppendLine($"    <span><b>Tool:</b> v{Esc(r.ToolVersion)}</span>");
        sb.AppendLine($"  </div>");
        sb.AppendLine($"  <div class='verdict {verdictClass}'>{Esc(verdictText)}</div>");
        sb.AppendLine($"  <p class='disclaimer'>This is a triage report. Each <b>DETECT</b> is a candidate for manual review by staff during the screenshare; it is not a guilty verdict on its own.</p>");
        sb.AppendLine("</header>");

        // ----- detection results card (categories) -----
        RenderCategoriesCard(sb, r, counts);

        // ----- PC info card -----
        if (r.Pc != null) RenderPcInfoCard(sb, r.Pc);

        // ----- accounts + discord cards (side-by-side) -----
        RenderAccountsCards(sb, r);

        // ----- mods table -----
        RenderModsTable(sb, r);

        // ----- detailed sections (raw scanner output) -----
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
                        sb.AppendLine($"        <div class='hash'>{Esc(entry.Hash)}</div>");
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
                      + " — local-only, no network exfiltration except optional Modrinth/VirusTotal hash lookups.</small></footer>");
        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    // -----------------------------------------------------------------

    private static void RenderCategoriesCard(StringBuilder sb, SessionReport r, CategoryCounts counts)
    {
        sb.AppendLine("<section class='card'>");
        sb.AppendLine("  <div class='card-head'>");
        sb.AppendLine("    <h2>Detection Results</h2>");
        sb.AppendLine($"    <p class='card-sub'>{counts.Total} total log(s) found across 5 categories</p>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class='cat-grid'>");
        AppendCategoryTile(sb, ResultCategory.Detects,    "Detects",    counts.Detects);
        AppendCategoryTile(sb, ResultCategory.Integrity,  "Integrity",  counts.Integrity);
        AppendCategoryTile(sb, ResultCategory.Warnings,   "Warnings",   counts.Warnings);
        AppendCategoryTile(sb, ResultCategory.Suspicious, "Suspicious", counts.Suspicious);
        AppendCategoryTile(sb, ResultCategory.Backstage,  "Backstage",  counts.Backstage);
        sb.AppendLine("  </div>");

        // Per-category lists (collapsible <details> elements).
        foreach (ResultCategory cat in Enum.GetValues<ResultCategory>())
        {
            if (cat == ResultCategory.Errors) continue;
            var matches = r.Sections
                .SelectMany(s => s.Results.Select(rs => (Section: s, Result: rs)))
                .Where(x => SessionReport.Categorize(x.Result) == cat)
                .ToList();
            if (matches.Count == 0) continue;

            sb.AppendLine("  <details class='cat-details'>");
            sb.AppendLine($"    <summary><b>{cat}</b> · <span class='count'>{matches.Count}</span></summary>");
            sb.AppendLine("    <ul class='cat-list'>");
            foreach (var (sec, res) in matches)
            {
                sb.Append("      <li>");
                sb.Append($"<span class='lbl-{res.Severity.ToString().ToLowerInvariant()}'>{res.Severity.ToString().ToUpperInvariant()}</span> ");
                sb.Append($"<b>{Esc(res.Title)}</b> ");
                sb.Append($"<span class='dim'>({Esc(sec.Title)})</span>");
                if (!string.IsNullOrEmpty(res.FilePath))
                    sb.Append($"<div><code class='path'>{Esc(res.FilePath)}</code></div>");
                sb.AppendLine("</li>");
            }
            sb.AppendLine("    </ul>");
            sb.AppendLine("  </details>");
        }

        sb.AppendLine("</section>");
    }

    private static void AppendCategoryTile(StringBuilder sb, ResultCategory cat, string label, int count)
    {
        var key = cat.ToString().ToLowerInvariant();
        sb.AppendLine($"    <div class='cat-tile cat-{key}'>");
        sb.AppendLine($"      <span class='cat-label'>{Esc(label)} Logs</span>");
        sb.AppendLine($"      <span class='cat-count'>{count}</span>");
        sb.AppendLine("    </div>");
    }

    private static void RenderPcInfoCard(StringBuilder sb, PcInfo pc)
    {
        sb.AppendLine("<section class='card'>");
        sb.AppendLine("  <div class='card-head'>");
        sb.AppendLine("    <h2>PC Information</h2>");
        sb.AppendLine("    <p class='card-sub'>Information about the user's PC</p>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <ul class='pc-list'>");
        if (pc.System         != null) sb.AppendLine(PcRow("system",  "System",       Esc(pc.System)));
        if (pc.BootTime       != null) sb.AppendLine(PcRow("boot",    "Boot Time",    $"{Esc(Ago(pc.BootTime.Value))} <span class='dim'>({pc.BootTime:yyyy-MM-dd HH:mm:ss})</span>"));
        if (pc.VpnStatus      != null) sb.AppendLine(PcRow(pc.VpnStatus == "no" ? "vpn-no" : "vpn-yes", "VPN", Esc(pc.VpnStatus) + (pc.VpnHits.Count > 0 ? "<div class='dim small'>" + string.Join(" · ", pc.VpnHits.Select(Esc)) + "</div>" : "")));
        if (pc.InstallDate    != null) sb.AppendLine(PcRow("install", "Install Date", $"{pc.InstallDate:yyyy-MM-dd HH:mm:ss}"));
        if (pc.Country        != null) sb.AppendLine(PcRow("country", "Country",      Esc(pc.Country)));
        if (pc.LastGameTime   != null) sb.AppendLine(PcRow("game",    "Last Game",    $"{Esc(Ago(pc.LastGameTime.Value))} <span class='dim'>({pc.LastGameTime:yyyy-MM-dd HH:mm:ss})</span>"));
        if (pc.LastRecycle    != null) sb.AppendLine(PcRow("recycle", "Recycle",      $"{Esc(Ago(pc.LastRecycle.Value))} <span class='dim'>({pc.LastRecycle:yyyy-MM-dd HH:mm:ss})</span>"));
        if (pc.DiscordInstall != null) sb.AppendLine(PcRow("discord", "Discord",      Esc(pc.DiscordInstall)));
        else                           sb.AppendLine(PcRow("discord", "Discord",      "<span class='dim'>not installed</span>"));
        var hw = new List<string>();
        if (pc.Cpu      != null) hw.Add($"<b>CPU:</b> {Esc(pc.Cpu)}");
        if (pc.Gpu      != null) hw.Add($"<b>GPU:</b> {Esc(pc.Gpu)}");
        if (pc.RamBytes != null) hw.Add($"<b>RAM:</b> {FormatBytes(pc.RamBytes.Value)}");
        foreach (var d in pc.Disks)
            hw.Add($"<b>{Esc(d.Name)}:</b> {Esc(d.Format ?? "?")} {FormatBytes(d.Size ?? 0)} <span class='dim'>(free {FormatBytes(d.Free ?? 0)})</span>");
        if (hw.Count > 0)
        {
            sb.AppendLine("    <li class='pc-row pc-hw'>");
            sb.AppendLine("      <span class='dot dot-hw'></span>");
            sb.AppendLine("      <span class='pc-label'>Hardware Stats</span>");
            sb.AppendLine("      <span class='pc-value'>" + string.Join(" · ", hw) + "</span>");
            sb.AppendLine("    </li>");
        }
        sb.AppendLine("  </ul>");
        sb.AppendLine("</section>");
    }

    private static string PcRow(string dot, string label, string value)
    {
        return $"    <li class='pc-row'><span class='dot dot-{dot}'></span><span class='pc-label'>{Esc(label)}</span><span class='pc-value'>{value}</span></li>";
    }

    private static void RenderAccountsCards(StringBuilder sb, SessionReport r)
    {
        if (r.McAccounts.Count == 0 && r.DiscordInstalls.Count == 0) return;

        sb.AppendLine("<section class='cards-row'>");

        // ----- alt MC accounts -----
        sb.AppendLine("  <div class='card half'>");
        sb.AppendLine("    <div class='card-head'>");
        sb.AppendLine($"      <h3>Accounts ({r.McAccounts.Count})</h3>");
        sb.AppendLine("      <p class='card-sub'>Alternative Minecraft accounts detected on disk</p>");
        sb.AppendLine("    </div>");
        if (r.McAccounts.Count == 0)
            sb.AppendLine("    <p class='empty'>No alt accounts detected.</p>");
        else
        {
            sb.AppendLine("    <ul class='acc-list'>");
            foreach (var a in r.McAccounts.OrderBy(x => x.Source).ThenBy(x => x.Username))
            {
                sb.AppendLine("      <li class='acc-row'>");
                sb.AppendLine($"        <div class='acc-name'>{Esc(a.Username)}</div>");
                sb.AppendLine($"        <div class='acc-meta'><span class='tag'>{Esc(a.Source)}</span>" +
                              (a.AccountType != null ? $" <span class='tag'>{Esc(a.AccountType)}</span>" : "") +
                              (a.Uuid != null ? $" <span class='dim small'>uuid {Esc(a.Uuid)}</span>" : "") +
                              "</div>");
                sb.AppendLine("      </li>");
            }
            sb.AppendLine("    </ul>");
        }
        sb.AppendLine("  </div>");

        // ----- discord installs (presence only) -----
        sb.AppendLine("  <div class='card half'>");
        sb.AppendLine("    <div class='card-head'>");
        sb.AppendLine($"      <h3>Discord ({r.DiscordInstalls.Count})</h3>");
        sb.AppendLine("      <p class='card-sub'>Discord installations detected. We do <b>not</b> read tokens, chats, or leveldb data.</p>");
        sb.AppendLine("    </div>");
        if (r.DiscordInstalls.Count == 0)
            sb.AppendLine("    <p class='empty'>Discord not installed.</p>");
        else
        {
            sb.AppendLine("    <ul class='acc-list'>");
            foreach (var d in r.DiscordInstalls)
            {
                sb.AppendLine("      <li class='acc-row'>");
                sb.AppendLine($"        <div class='acc-name'>{Esc(d.Variant)}{(d.Version != null ? " <span class='dim small'>v" + Esc(d.Version) + "</span>" : "")}{(d.IsRunning ? " <span class='tag tag-run'>running</span>" : "")}</div>");
                sb.AppendLine($"        <div class='acc-meta'><code class='path'>{Esc(d.InstallPath)}</code></div>");
                sb.AppendLine("      </li>");
            }
            sb.AppendLine("    </ul>");
        }
        sb.AppendLine("  </div>");

        sb.AppendLine("</section>");
    }

    private static void RenderModsTable(StringBuilder sb, SessionReport r)
    {
        if (r.Mods.Count == 0) return;

        int verified    = r.Mods.Count(m => m.Verification == ModVerification.Verified);
        int notVerified = r.Mods.Count(m => m.Verification == ModVerification.NotVerified);
        int unknown     = r.Mods.Count(m => m.Verification == ModVerification.Unknown
                                         || m.Verification == ModVerification.Skipped);

        sb.AppendLine("<section class='card'>");
        sb.AppendLine("  <div class='card-head'>");
        sb.AppendLine($"    <h2>Mods Logs ({r.Mods.Count})</h2>");
        sb.AppendLine($"    <p class='card-sub'>Mod jars detected. {verified} verified · {notVerified} not verified · {unknown} unknown.</p>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <ul class='mods-list'>");
        foreach (var m in r.Mods.OrderByDescending(m => m.Modified))
        {
            var verCls = m.Verification switch
            {
                ModVerification.Verified    => "ver-yes",
                ModVerification.NotVerified => "ver-no",
                ModVerification.Skipped     => "ver-skip",
                _                            => "ver-unknown",
            };
            var verLabel = m.Verification switch
            {
                ModVerification.Verified    => "VERIFIED",
                ModVerification.NotVerified => "NOT VERIFIED",
                ModVerification.Skipped     => "SKIPPED",
                _                            => "UNKNOWN",
            };

            sb.AppendLine($"    <li class='mod-row {verCls}'>");
            sb.AppendLine("      <div class='mod-head'>");
            sb.AppendLine($"        <span class='mod-name'>{Esc(m.FileName)}</span>");
            sb.AppendLine($"        <span class='mod-badge {verCls}'>{verLabel}</span>");
            sb.AppendLine($"        <span class='mod-size'>{FormatBytes(m.Size)}</span>");
            sb.AppendLine("      </div>");
            sb.AppendLine("      <div class='mod-meta'>");
            if (m.RegistryName != null)
                sb.Append($"        <span class='dim small'>Registry: <b>{Esc(m.RegistryName)}</b>{(m.RegistryTitle != null ? " · " + Esc(m.RegistryTitle) : "")}</span> ");
            sb.Append($"<span class='dim small'>Modified: {m.Modified:yyyy-MM-dd HH:mm}</span>");
            if (!string.IsNullOrEmpty(m.Sha1))
                sb.Append($" <span class='dim small'>sha1 {Esc(m.Sha1[..Math.Min(12, m.Sha1.Length)])}…</span>");
            sb.AppendLine();
            sb.AppendLine("      </div>");
            if (!string.IsNullOrEmpty(m.RegistryDownloadUrl))
                sb.AppendLine($"      <div class='mod-link'><a href='{Esc(m.RegistryDownloadUrl)}' rel='noopener'>{Esc(m.RegistryDownloadUrl)}</a></div>");
            sb.AppendLine($"      <div class='mod-path'><code class='path'>{Esc(m.FilePath)}</code></div>");
            sb.AppendLine("    </li>");
        }
        sb.AppendLine("  </ul>");
        sb.AppendLine("</section>");
    }

    // -----------------------------------------------------------------

    private static string Esc(string? s) => s == null ? "" : WebUtility.HtmlEncode(s);

    private static string Ago(DateTime when)
    {
        var diff = DateTime.Now - when;
        if (diff < TimeSpan.Zero) return when.ToString("yyyy-MM-dd HH:mm");
        if (diff < TimeSpan.FromMinutes(1))  return $"{(int)diff.TotalSeconds}s ago";
        if (diff < TimeSpan.FromHours(1))    return $"{(int)diff.TotalMinutes} min ago";
        if (diff < TimeSpan.FromDays(1))     return $"{(int)diff.TotalHours}h ago";
        if (diff < TimeSpan.FromDays(60))    return $"{(int)diff.TotalDays}d ago";
        return $"{(int)(diff.TotalDays / 30)} months ago";
    }

    private static string FormatBytes(long b)
    {
        if (b <= 0) return "0";
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double v = b;
        int u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        return $"{v:0.##} {units[u]}";
    }

    private static string Css() => @"
:root { color-scheme: light dark; --bg: #0e1116; --bg2: #131820; --bg3: #1a1f2b; --bd: #2a313e; --fg: #e6e6e6; --dim: #aaa; --link: #6cb6ff; }
body { font: 14px/1.4 -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0; background: var(--bg); color: var(--fg); }

header.top { padding: 24px 32px; background: linear-gradient(180deg, #1a1f2b, #0e1116); border-bottom: 1px solid var(--bd); }
header.top h1 { margin: 0 0 8px 0; font-size: 24px; }
.meta { display: flex; flex-wrap: wrap; gap: 12px 24px; font-size: 13px; color: var(--dim); }
.meta span b { color: #ddd; font-weight: 600; }
.verdict { display: inline-block; margin-top: 14px; padding: 8px 16px; border-radius: 6px; font-weight: 700; font-size: 16px; }
.verdict-clean { background: #1d3823; color: #b3f0c1; }
.verdict-warn  { background: #3a341a; color: #f5d97c; }
.verdict-hit   { background: #4a1c1c; color: #ffb3b3; }
.disclaimer { margin-top: 12px; color: var(--dim); font-size: 12px; }

.card { margin: 18px 32px; background: var(--bg2); border: 1px solid var(--bd); border-radius: 10px; padding: 20px 24px; }
.card.half { flex: 1 1 0; min-width: 0; }
.cards-row { display: flex; gap: 16px; margin: 18px 32px; }
.card-head h2, .card-head h3 { margin: 0 0 4px 0; font-size: 18px; }
.card-head .card-sub { margin: 0 0 14px 0; color: var(--dim); font-size: 12px; }

.cat-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 14px; }
.cat-tile { background: var(--bg3); border: 1px solid var(--bd); border-radius: 8px; padding: 12px 14px; display: flex; justify-content: space-between; align-items: center; }
.cat-tile .cat-label { color: var(--dim); font-size: 13px; }
.cat-tile .cat-count { font-weight: 700; font-size: 18px; padding: 2px 10px; border-radius: 6px; min-width: 28px; text-align: center; background: rgba(255,255,255,0.06); }
.cat-detects    .cat-count { color: #ffb3b3; background: rgba(255, 80, 80, 0.12); }
.cat-integrity  .cat-count { color: #b3f0c1; background: rgba(120, 220, 120, 0.10); }
.cat-warnings   .cat-count { color: #f5d97c; background: rgba(245, 217, 124, 0.12); }
.cat-suspicious .cat-count { color: #a3c4e6; background: rgba(120, 170, 240, 0.10); }
.cat-backstage  .cat-count { color: #cdb1f2; background: rgba(180, 130, 240, 0.10); }

.cat-details { margin-top: 8px; border: 1px solid var(--bd); border-radius: 6px; padding: 6px 12px; background: rgba(255,255,255,0.02); }
.cat-details summary { cursor: pointer; font-size: 13px; color: var(--dim); }
.cat-details summary b { color: #ddd; }
.cat-details summary .count { background: rgba(255,255,255,0.06); padding: 1px 8px; border-radius: 4px; }
.cat-list { margin: 8px 0 4px 0; padding-left: 16px; }
.cat-list li { margin: 4px 0; }
.lbl-hit  { color: #ffb3b3; font-weight: 700; font-size: 11px; padding: 1px 6px; border-radius: 3px; background: rgba(255, 80, 80, 0.12); }
.lbl-warn { color: #f5d97c; font-weight: 700; font-size: 11px; padding: 1px 6px; border-radius: 3px; background: rgba(245, 217, 124, 0.12); }
.lbl-info { color: #a3c4e6; font-weight: 700; font-size: 11px; padding: 1px 6px; border-radius: 3px; background: rgba(120, 170, 240, 0.10); }
.lbl-ok   { color: #b3f0c1; font-weight: 700; font-size: 11px; padding: 1px 6px; border-radius: 3px; background: rgba(120, 220, 120, 0.10); }
.lbl-error { color: #ddd; font-weight: 700; font-size: 11px; padding: 1px 6px; border-radius: 3px; background: rgba(255,255,255,0.06); }

.pc-list { list-style: none; margin: 0; padding: 0; }
.pc-row { display: flex; align-items: center; gap: 12px; padding: 10px 0; border-bottom: 1px dashed var(--bd); }
.pc-row:last-child { border-bottom: none; }
.pc-label { color: var(--dim); flex: 1 1 0; }
.pc-value { font-weight: 600; text-align: right; }
.pc-row.pc-hw .pc-value { font-weight: 400; color: var(--dim); font-size: 12px; }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex: 0 0 auto; }
.dot-system  { background: #6cb6ff; }
.dot-boot    { background: #6ce6a0; }
.dot-vpn-no  { background: #ff6c6c; }
.dot-vpn-yes { background: #ff9d3a; }
.dot-install { background: #b18cf2; }
.dot-country { background: #ff9d3a; }
.dot-game    { background: #6ce6a0; }
.dot-recycle { background: #ff9d3a; }
.dot-discord { background: #5865f2; }
.dot-hw      { background: #6cb6ff; }

.acc-list { list-style: none; margin: 0; padding: 0; }
.acc-row { padding: 10px 12px; margin: 6px 0; background: var(--bg3); border: 1px solid var(--bd); border-radius: 8px; }
.acc-name { font-family: ui-monospace, monospace; font-weight: 700; }
.acc-meta { margin-top: 4px; font-size: 12px; color: var(--dim); }
.tag { display: inline-block; padding: 1px 6px; border-radius: 3px; background: var(--bd); color: #c0c0c0; font-size: 11px; font-family: ui-monospace, monospace; }
.tag-run { background: #1d3823; color: #b3f0c1; }

.mods-list { list-style: none; margin: 0; padding: 0; }
.mod-row { padding: 12px 14px; margin: 8px 0; background: var(--bg3); border: 1px solid var(--bd); border-radius: 8px; border-left: 4px solid var(--bd); }
.mod-row.ver-yes     { border-left-color: #6ce6a0; }
.mod-row.ver-no      { border-left-color: #ff9d3a; }
.mod-row.ver-skip    { border-left-color: #888; }
.mod-row.ver-unknown { border-left-color: #888; }
.mod-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.mod-name { font-family: ui-monospace, monospace; font-weight: 700; flex: 1 1 auto; min-width: 0; word-break: break-all; }
.mod-badge { font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px; }
.mod-badge.ver-yes     { background: rgba(120, 220, 120, 0.12); color: #b3f0c1; }
.mod-badge.ver-no      { background: rgba(255, 158, 60, 0.18);  color: #ffd09d; }
.mod-badge.ver-skip    { background: rgba(255,255,255,0.06); color: #aaa; }
.mod-badge.ver-unknown { background: rgba(255,255,255,0.06); color: #aaa; }
.mod-size { font-size: 12px; color: var(--dim); font-family: ui-monospace, monospace; }
.mod-meta { margin-top: 6px; }
.mod-link { margin-top: 6px; font-size: 12px; word-break: break-all; }
.mod-link a { color: var(--link); }
.mod-path { margin-top: 6px; }

nav.toc { padding: 16px 32px; background: var(--bg2); border-bottom: 1px solid var(--bd); border-top: 1px solid var(--bd); margin-top: 24px; }
nav.toc h2 { margin: 0 0 8px 0; font-size: 14px; color: var(--dim); text-transform: uppercase; letter-spacing: 1px; }
nav.toc ol { margin: 0; padding-left: 24px; }
nav.toc a { color: var(--link); text-decoration: none; }
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
.sev-err, .sev-error { color: #ddd; }
code.path { font-family: ui-monospace, monospace; font-size: 12px; background: var(--bg3); padding: 2px 6px; border-radius: 3px; word-break: break-all; }
.hash { font-family: ui-monospace, monospace; font-size: 11px; color: var(--dim); margin-top: 4px; word-break: break-all; }
pre.detail { font-family: ui-monospace, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-word; background: var(--bg2); padding: 6px 8px; border-radius: 4px; margin: 6px 0 0 0; max-width: 60vw; }
.ts { color: #888; font-family: ui-monospace, monospace; font-size: 12px; white-space: nowrap; }
.dim { color: var(--dim); }
.small { font-size: 11px; }
.empty { color: #888; font-style: italic; }
.c-hit  { background: #4a1c1c; color: #ffb3b3; padding: 1px 6px; border-radius: 3px; font-family: ui-monospace, monospace; font-size: 11px; }
.c-warn { background: #3a341a; color: #f5d97c; padding: 1px 6px; border-radius: 3px; font-family: ui-monospace, monospace; font-size: 11px; }
footer { padding: 16px 32px; color: #666; font-size: 12px; }

@media (max-width: 900px) {
  .cat-grid { grid-template-columns: repeat(2, 1fr); }
  .cards-row { flex-direction: column; }
}
@media (prefers-color-scheme: light) {
  :root { --bg: #f7f8fa; --bg2: #ffffff; --bg3: #eef0f4; --bd: #e2e6ee; --fg: #222; --dim: #555; --link: #1759c4; }
  body { background: var(--bg); color: var(--fg); }
  header.top { background: linear-gradient(180deg, #fff, #f0f2f6); border-bottom-color: #ddd; }
  .meta span b { color: #222; }
  nav.toc { background: var(--bg2); border-top-color: var(--bd); border-bottom-color: var(--bd); }
  section.sec { border-bottom-color: var(--bd); }
  th, td { border-bottom-color: var(--bd); }
  .cat-tile, .acc-row, .mod-row { background: var(--bg3); border-color: var(--bd); }
  .cat-detects    .cat-count { background: rgba(255, 80, 80, 0.10); color: #b80b0b; }
  .cat-integrity  .cat-count { background: rgba(40, 160, 60, 0.10); color: #176d2c; }
  .cat-warnings   .cat-count { background: rgba(220, 170, 30, 0.18); color: #7a5a03; }
  .cat-suspicious .cat-count { background: rgba(40, 110, 200, 0.10); color: #0c4a91; }
  .cat-backstage  .cat-count { background: rgba(120, 70, 200, 0.10); color: #4f2da6; }
  .lbl-hit  { background: rgba(255, 80, 80, 0.10); color: #b80b0b; }
  .lbl-warn { background: rgba(220, 170, 30, 0.18); color: #7a5a03; }
  .lbl-info { background: rgba(40, 110, 200, 0.10); color: #0c4a91; }
  .lbl-ok   { background: rgba(40, 160, 60, 0.10); color: #176d2c; }
  .verdict-clean { background: #def6e3; color: #176d2c; }
  .verdict-warn  { background: #fbeec1; color: #7a5a03; }
  .verdict-hit   { background: #fbd3d3; color: #b80b0b; }
  .mod-badge.ver-yes     { background: #def6e3; color: #176d2c; }
  .mod-badge.ver-no      { background: #fde0c1; color: #8a4a00; }
  code.path { background: var(--bg3); }
  pre.detail { background: var(--bg3); }
  .tag { background: var(--bd); color: #333; }
  .tag-run { background: #def6e3; color: #176d2c; }
}
";
}
