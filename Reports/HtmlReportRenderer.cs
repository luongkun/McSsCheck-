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
            var psi = new ProcessStartInfo { FileName = filePath, UseShellExecute = true };
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
        // v0.9.0: stronger verdict wording requested by users — staff want a
        // big, readable "this user is cheating / suspicious / looks clean"
        // line at the top of the report, not just a bare count.
        string verdictClass, verdictHtml;
        if (counts.Detects > 0)
        {
            verdictClass = "verdict-hit";
            verdictHtml  = $"This user is <b>cheating</b> <span class='verdict-sub'>({counts.Detects} detect{(counts.Detects == 1 ? "" : "s")})</span>";
        }
        else if (counts.Warnings > 0)
        {
            verdictClass = "verdict-warn";
            verdictHtml  = $"This user is <b>suspicious</b> <span class='verdict-sub'>({counts.Warnings} warning{(counts.Warnings == 1 ? "" : "s")})</span>";
        }
        else
        {
            verdictClass = "verdict-clean";
            verdictHtml  = "This user looks <b>clean</b> <span class='verdict-sub'>(no detects)</span>";
        }

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
        sb.AppendLine("<header class='top'>");
        sb.AppendLine("  <div class='top-row'>");
        sb.AppendLine("    <h1>McSsCheck report</h1>");
        // Export button — opens a small JS handler that dumps the current
        // report as JSON. Works fully offline since the report is a single
        // self-contained HTML file.
        sb.AppendLine("    <button type='button' class='export-btn' id='mcss-export' title='Export report as JSON'>");
        sb.AppendLine("      <span class='export-ico'>&#x1F4E5;</span><span class='export-label'>Export</span>");
        sb.AppendLine("    </button>");
        sb.AppendLine("  </div>");
        sb.AppendLine("  <div class='meta'>");
        sb.AppendLine($"    <span><b>Host:</b> {Esc(r.Hostname)}</span>");
        sb.AppendLine($"    <span><b>User:</b> {Esc(r.Username)}</span>");
        sb.AppendLine($"    <span><b>Started:</b> {r.StartedAt:yyyy-MM-dd HH:mm:ss}</span>");
        sb.AppendLine($"    <span><b>Finished:</b> {r.FinishedAt?.ToString("yyyy-MM-dd HH:mm:ss") ?? "-"}</span>");
        if (r.FinishedAt.HasValue)
        {
            var dur = r.FinishedAt.Value - r.StartedAt;
            sb.AppendLine($"    <span><b>Duration:</b> {Esc(FormatDuration(dur))}</span>");
        }
        sb.AppendLine($"    <span><b>Tool:</b> v{Esc(r.ToolVersion)}</span>");
        sb.AppendLine("  </div>");
        sb.AppendLine($"  <div class='verdict {verdictClass}'>{verdictHtml}</div>");
        sb.AppendLine("  <p class='disclaimer'>This is a triage report. Each <b>DETECT</b> is a candidate for manual review by staff during the screenshare; it is not a guilty verdict on its own.</p>");
        sb.AppendLine("</header>");

        // Embed report data as JSON so the Export button can download it.
        sb.AppendLine("<script id='mcss-data' type='application/json'>");
        sb.AppendLine(BuildJsonPayload(r, counts));
        sb.AppendLine("</script>");

        // ----- detection results card with tabs -----
        RenderCategoriesCard(sb, r, counts);

        // ----- PC info card -----
        if (r.Pc != null) RenderPcInfoCard(sb, r.Pc);

        // ----- accounts + discord cards (side-by-side) -----
        RenderAccountsCards(sb, r);

        // ----- mods table -----
        RenderModsTable(sb, r);

        // ----- detailed sections (raw scanner output) -----
        // v0.8.0: collapsed by default — raw scanner sections are noisy and
        // most staff only need the curated cards above. Click the summary to
        // expand if you want the full log.
        sb.AppendLine("<details class='raw-toggle'>" +
                      "<summary>Raw scanner sections (full log)</summary>");

        // Severity filter bar — JS toggles row visibility & remembers state in
        // localStorage so a refresh keeps the staff member's last view.
        // v0.8.0: default to HIT+WARN visible (OK / INFO / Err hidden) so the
        // initial expand isn't a wall of integrity-pass and informational rows.
        sb.AppendLine("<div class='sev-filter' role='toolbar' aria-label='Filter by severity'>");
        sb.AppendLine("  <span class='sev-filter-label'>Show:</span>");
        sb.AppendLine("  <button type='button' class='sev-btn sev-btn-all'         data-sev='all'>All</button>");
        sb.AppendLine("  <button type='button' class='sev-btn sev-btn-hit  active' data-sev='hit'>Hit</button>");
        sb.AppendLine("  <button type='button' class='sev-btn sev-btn-warn active' data-sev='warn'>Warn</button>");
        sb.AppendLine("  <button type='button' class='sev-btn sev-btn-ok'          data-sev='ok'>OK</button>");
        sb.AppendLine("  <button type='button' class='sev-btn sev-btn-info'        data-sev='info'>Info</button>");
        sb.AppendLine("  <button type='button' class='sev-btn sev-btn-err'         data-sev='error'>Err</button>");
        sb.AppendLine("</div>");

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
                    sb.AppendLine("    </tr>");
                }
                sb.AppendLine("    </tbody>");
                sb.AppendLine("  </table>");
            }
            sb.AppendLine("</section>");
        }
        sb.AppendLine("</details>");

        sb.AppendLine("<footer><small>Generated by McSsCheck v" + Esc(r.ToolVersion)
                      + " — local-only, no network exfiltration except optional Modrinth/VirusTotal hash lookups.</small></footer>");
        sb.AppendLine("<script>" + FilterJs() + "</script>");
        sb.AppendLine("<script>" + ExportJs() + "</script>");
        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    /// <summary>
    /// Build a structured JSON payload of the report so the Export button
    /// can hand the staff member something machine-readable. Embedded as
    /// <c>&lt;script type='application/json' id='mcss-data'&gt;</c> in the
    /// HTML so it travels with the report file even after archiving.
    /// </summary>
    private static string BuildJsonPayload(SessionReport r, CategoryCounts counts)
    {
        var sb = new StringBuilder();
        sb.Append('{');
        sb.Append("\"tool\":").Append(JsonStr("McSsCheck")).Append(',');
        sb.Append("\"version\":").Append(JsonStr(r.ToolVersion)).Append(',');
        sb.Append("\"hostname\":").Append(JsonStr(r.Hostname)).Append(',');
        sb.Append("\"username\":").Append(JsonStr(r.Username)).Append(',');
        sb.Append("\"os\":").Append(JsonStr(r.OsVersion)).Append(',');
        sb.Append("\"startedAt\":").Append(JsonStr(r.StartedAt.ToString("yyyy-MM-ddTHH:mm:ss"))).Append(',');
        sb.Append("\"finishedAt\":").Append(r.FinishedAt.HasValue
            ? JsonStr(r.FinishedAt.Value.ToString("yyyy-MM-ddTHH:mm:ss")) : "null").Append(',');
        sb.Append("\"counts\":{");
        sb.Append("\"detects\":").Append(counts.Detects).Append(',');
        sb.Append("\"integrity\":").Append(counts.Integrity).Append(',');
        sb.Append("\"warnings\":").Append(counts.Warnings).Append(',');
        sb.Append("\"suspicious\":").Append(counts.Suspicious).Append(',');
        sb.Append("\"backstage\":").Append(counts.Backstage).Append(',');
        sb.Append("\"errors\":").Append(counts.Errors);
        sb.Append("},");

        sb.Append("\"discordAccounts\":[");
        for (int i = 0; i < r.DiscordAccounts.Count; i++)
        {
            if (i > 0) sb.Append(',');
            var a = r.DiscordAccounts[i];
            sb.Append('{');
            sb.Append("\"userId\":").Append(JsonStr(a.UserId)).Append(',');
            sb.Append("\"username\":").Append(JsonStr(a.Username)).Append(',');
            sb.Append("\"globalName\":").Append(a.GlobalName == null ? "null" : JsonStr(a.GlobalName)).Append(',');
            sb.Append("\"avatarHash\":").Append(a.AvatarHash == null ? "null" : JsonStr(a.AvatarHash)).Append(',');
            sb.Append("\"clientVariant\":").Append(JsonStr(a.ClientVariant));
            sb.Append('}');
        }
        sb.Append("],");

        sb.Append("\"sections\":[");
        for (int si = 0; si < r.Sections.Count; si++)
        {
            if (si > 0) sb.Append(',');
            var s = r.Sections[si];
            sb.Append('{');
            sb.Append("\"title\":").Append(JsonStr(s.Title)).Append(',');
            sb.Append("\"results\":[");
            for (int ri = 0; ri < s.Results.Count; ri++)
            {
                if (ri > 0) sb.Append(',');
                var res = s.Results[ri];
                sb.Append('{');
                sb.Append("\"source\":").Append(JsonStr(res.Source)).Append(',');
                sb.Append("\"severity\":").Append(JsonStr(res.Severity.ToString())).Append(',');
                sb.Append("\"title\":").Append(JsonStr(res.Title)).Append(',');
                sb.Append("\"detail\":").Append(res.Detail == null ? "null" : JsonStr(res.Detail)).Append(',');
                sb.Append("\"filePath\":").Append(res.FilePath == null ? "null" : JsonStr(res.FilePath)).Append(',');
                sb.Append("\"hash\":").Append(res.Hash == null ? "null" : JsonStr(res.Hash)).Append(',');
                sb.Append("\"timestamp\":").Append(res.Timestamp.HasValue
                    ? JsonStr(res.Timestamp.Value.ToString("yyyy-MM-ddTHH:mm:ss")) : "null").Append(',');
                sb.Append("\"tags\":[");
                if (res.Tags is { Count: > 0 })
                {
                    for (int ti = 0; ti < res.Tags.Count; ti++)
                    {
                        if (ti > 0) sb.Append(',');
                        sb.Append(JsonStr(res.Tags[ti]));
                    }
                }
                sb.Append(']');
                sb.Append('}');
            }
            sb.Append(']');
            sb.Append('}');
        }
        sb.Append(']');
        sb.Append('}');
        return sb.ToString();
    }

    /// <summary>
    /// Minimal JSON string escaper — handles the characters the spec
    /// requires (quote, backslash, control chars). Avoids pulling in
    /// System.Text.Json because the payload is tiny and we want zero
    /// allocations beyond the StringBuilder.
    /// </summary>
    private static string JsonStr(string? s)
    {
        if (s == null) return "null";
        var sb = new StringBuilder(s.Length + 2);
        sb.Append('"');
        foreach (var c in s)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '"':  sb.Append("\\\""); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                case '<':  sb.Append("\\u003c"); break;  // avoid </script> injection if string contains script close tag
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                    else          sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }

    /// <summary>
    /// Vanilla-JS click handler for the "Export" button. Reads the embedded
    /// JSON payload (added next to the header) and triggers a download as
    /// <c>mcss-report-&lt;host&gt;-&lt;timestamp&gt;.json</c>. Self-contained,
    /// no dependencies, works fully offline.
    /// </summary>
    private static string ExportJs() => @"
(function(){
  // ----- Export button: download embedded JSON payload as a file -----
  var btn = document.getElementById('mcss-export');
  var dataNode = document.getElementById('mcss-data');
  if (btn && dataNode) {
    btn.addEventListener('click', function(){
      try {
        var json = dataNode.textContent.trim();
        var payload;
        try { payload = JSON.parse(json); } catch(e) { payload = null; }
        var blob = new Blob([json], { type: 'application/json;charset=utf-8' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        var host = (payload && payload.hostname) ? String(payload.hostname).replace(/[^a-zA-Z0-9_-]/g, '_') : 'host';
        var ts = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);
        a.href = url;
        a.download = 'mcss-report-' + host + '-' + ts + '.json';
        document.body.appendChild(a);
        a.click();
        setTimeout(function(){
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
        }, 0);
      } catch (err) {
        alert('Export failed: ' + (err && err.message ? err.message : err));
      }
    });
  }

  // ----- Discord-account ID copy buttons -----
  document.querySelectorAll('.dc-btn-copy').forEach(function(b){
    b.addEventListener('click', function(){
      var v = b.getAttribute('data-copy') || '';
      var done = function(){
        var prev = b.textContent;
        b.textContent = '\u2713'; // check mark briefly
        setTimeout(function(){ b.textContent = prev; }, 900);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(v).then(done).catch(function(){
          // Fallback for file:// origins where clipboard API may be blocked.
          var ta = document.createElement('textarea');
          ta.value = v; document.body.appendChild(ta);
          ta.select(); try { document.execCommand('copy'); } catch(_){}
          document.body.removeChild(ta); done();
        });
      } else {
        var ta = document.createElement('textarea');
        ta.value = v; document.body.appendChild(ta);
        ta.select(); try { document.execCommand('copy'); } catch(_){}
        document.body.removeChild(ta); done();
      }
    });
  });
})();
";

    /// <summary>
    /// Tiny vanilla-JS filter for the raw-section table rows. State is
    /// persisted to <c>localStorage</c> per browser so a refresh keeps the
    /// staff member's view.
    ///
    /// v0.8.0: default state is HIT+WARN only (OK / INFO / Err hidden) to keep
    /// the initial view focused on actionable rows. Existing localStorage
    /// preferences (key <c>mcss-sev-filter</c>) are still respected.
    /// </summary>
    private static string FilterJs() => @"
(function(){
  var KEY = 'mcss-sev-filter';
  var SEVS = ['hit','warn','ok','info','error'];
  var btns = document.querySelectorAll('.sev-btn');
  if (!btns.length) return;

  // Read previous state from localStorage, otherwise default to HIT+WARN only.
  var state = (function(){
    try {
      var raw = localStorage.getItem(KEY);
      if (raw) return JSON.parse(raw);
    } catch(e) {}
    return { hit: true, warn: true, ok: false, info: false, error: false };
  })();

  function persist(){
    try { localStorage.setItem(KEY, JSON.stringify(state)); } catch(e) {}
  }

  function apply(){
    SEVS.forEach(function(sev){
      var visible = !!state[sev];
      document.querySelectorAll('tr.row-' + sev).forEach(function(tr){
        tr.style.display = visible ? '' : 'none';
      });
    });
    btns.forEach(function(b){
      var sev = b.getAttribute('data-sev');
      if (sev === 'all') {
        var allOn = SEVS.every(function(x){ return state[x]; });
        b.classList.toggle('active', allOn);
      } else {
        b.classList.toggle('active', !!state[sev]);
      }
    });
  }

  btns.forEach(function(b){
    b.addEventListener('click', function(){
      var sev = b.getAttribute('data-sev');
      if (sev === 'all') {
        var allOn = SEVS.every(function(x){ return state[x]; });
        SEVS.forEach(function(x){ state[x] = !allOn; });
      } else {
        state[sev] = !state[sev];
      }
      persist();
      apply();
    });
  });

  apply();
})();
";

    // -----------------------------------------------------------------

    private static void RenderCategoriesCard(StringBuilder sb, SessionReport r, CategoryCounts counts)
    {
        // Bucket every result by category once, sorted to keep highest-severity first.
        var buckets = new Dictionary<ResultCategory, List<(SessionReport.Section Section, ScanResult Result)>>();
        foreach (ResultCategory cat in Enum.GetValues<ResultCategory>())
            buckets[cat] = new();
        foreach (var sec in r.Sections)
            foreach (var res in sec.Results)
                buckets[SessionReport.Categorize(res)].Add((sec, res));

        sb.AppendLine("<section class='card'>");
        sb.AppendLine("  <div class='card-head'>");
        sb.AppendLine("    <h2>Detection Results</h2>");
        sb.AppendLine($"    <p class='card-sub'>{counts.Total} total log(s) found across 5 categories — click a tab to view that section.</p>");
        sb.AppendLine("  </div>");

        // Tab buttons (which one is active is controlled by hidden radio inputs below).
        sb.AppendLine("  <div class='cat-tabs'>");
        AppendTabButton(sb, "detects",    "Detects",    counts.Detects,    isFirst: true);
        AppendTabButton(sb, "integrity",  "Integrity",  counts.Integrity);
        AppendTabButton(sb, "warnings",   "Warnings",   counts.Warnings);
        AppendTabButton(sb, "suspicious", "Suspicious", counts.Suspicious);
        AppendTabButton(sb, "backstage",  "Backstage",  counts.Backstage);
        sb.AppendLine("  </div>");

        // The hidden radios drive which pane is shown via the CSS sibling selector.
        // (Pure CSS, no JavaScript needed.)
        sb.AppendLine("  <input type='radio' name='cat' id='cat-detects' class='cat-radio' checked>");
        sb.AppendLine("  <input type='radio' name='cat' id='cat-integrity' class='cat-radio'>");
        sb.AppendLine("  <input type='radio' name='cat' id='cat-warnings' class='cat-radio'>");
        sb.AppendLine("  <input type='radio' name='cat' id='cat-suspicious' class='cat-radio'>");
        sb.AppendLine("  <input type='radio' name='cat' id='cat-backstage' class='cat-radio'>");

        sb.AppendLine("  <div class='cat-panes'>");
        AppendPane(sb, "detects",    "Detects Logs",    "Strong indicators of cheat client usage. Each card is a candidate for manual review.", buckets[ResultCategory.Detects]);
        AppendPane(sb, "integrity",  "Integrity Logs",  "Checks that passed cleanly. These confirm what was looked at.",                          buckets[ResultCategory.Integrity]);
        AppendPane(sb, "warnings",   "Warnings Logs",   "Things worth a closer look — not necessarily cheating, but unusual.",                    buckets[ResultCategory.Warnings]);
        AppendPane(sb, "suspicious", "Suspicious Logs", "Informational entries that may be relevant in context.",                                 buckets[ResultCategory.Suspicious]);
        AppendPane(sb, "backstage",  "Backstage Logs",  "Hidden / staff-only entries (folders with the system+hidden attributes, etc.).",         buckets[ResultCategory.Backstage]);
        sb.AppendLine("  </div>");

        sb.AppendLine("</section>");
    }

    private static void AppendTabButton(StringBuilder sb, string key, string label, int count, bool isFirst = false)
    {
        sb.AppendLine($"    <label for='cat-{key}' class='cat-tab cat-tab-{key}{(isFirst ? " cat-tab-first" : "")}'>");
        sb.AppendLine($"      <span class='tab-label'>{Esc(label)} Logs</span>");
        sb.AppendLine($"      <span class='tab-count'>{count}</span>");
        sb.AppendLine("    </label>");
    }

    private static void AppendPane(StringBuilder sb, string key, string title, string blurb,
                                   List<(SessionReport.Section Section, ScanResult Result)> items)
    {
        sb.AppendLine($"    <div class='pane pane-{key}'>");
        sb.AppendLine($"      <div class='pane-head'>");
        sb.AppendLine($"        <h3>{Esc(title)}</h3>");
        sb.AppendLine($"        <p class='card-sub'>{Esc(blurb)}</p>");
        sb.AppendLine("      </div>");

        if (items.Count == 0)
        {
            sb.AppendLine("      <p class='empty'>(no entries in this category)</p>");
            sb.AppendLine("    </div>");
            return;
        }

        // v0.8.0: deduplicate findings that point at the same cheat client. A
        // typical Atermys/Koid hit fires from Process+Recent+Registry — that's
        // 3 separate cards in v0.7.0, all saying the same thing. We now group
        // by cheat-keyword tag (or Source+Title for non-keyword findings) and
        // render ONE card per group, with the other sources collapsed into
        // "Show details".
        var groups = items
            .GroupBy(x => DedupeKey(x.Result))
            .Select(g =>
            {
                var ordered = g.OrderByDescending(x => SevRank(x.Result.Severity))
                               .ThenBy(x => x.Section.Title, StringComparer.Ordinal)
                               .ThenBy(x => x.Result.Title, StringComparer.Ordinal)
                               .ToList();
                var primary = ordered[0];
                var extras  = ordered.Skip(1).ToList();
                return (primary.Section, primary.Result, extras);
            })
            .OrderByDescending(g => SevRank(g.Result.Severity))
            .ThenBy(g => g.Result.Title, StringComparer.Ordinal)
            .ToList();

        // Two layouts:
        //  - "headline" cards (Hit / strong-warn) — large, 2-col grid, top of pane
        //  - "row" cards (Ok / Info / Backstage) — single-column compact rows, bottom of pane
        var headline = groups.Where(g => g.Result.Severity == Severity.Hit
                                       || (g.Result.Severity == Severity.Warn && key == "warnings"))
                             .ToList();
        var rows = groups.Except(headline).ToList();

        if (headline.Count > 0)
        {
            sb.AppendLine("      <div class='detect-grid'>");
            foreach (var g in headline) AppendDetectCard(sb, g.Section, g.Result, g.extras);
            sb.AppendLine("      </div>");
        }
        if (rows.Count > 0)
        {
            sb.AppendLine("      <div class='detect-rows'>");
            foreach (var g in rows) AppendDetectRow(sb, g.Section, g.Result, g.extras);
            sb.AppendLine("      </div>");
        }

        sb.AppendLine("    </div>");
    }

    private static void AppendDetectCard(StringBuilder sb,
        SessionReport.Section sec, ScanResult res,
        List<(SessionReport.Section Section, ScanResult Result)> extras)
    {
        bool active = IsActive(res) || extras.Any(x => IsActive(x.Result));
        var statusTag = active ? "Boot instance" : "Out of instance";
        var statusCls = active ? "tag-active" : "tag-inactive";
        var sevCls    = res.Severity == Severity.Hit ? "sev-hit"
                       : res.Severity == Severity.Warn ? "sev-warn"
                       : "sev-info";

        // v0.8.0: card layout intentionally compact — icon + tag + title + path
        // + Show details. The free-form description block has been dropped
        // because most staff only need the title to recognise the cheat.
        sb.AppendLine($"        <div class='detect-card {sevCls}'>");
        sb.AppendLine("          <div class='detect-head'>");
        sb.AppendLine($"            <div class='detect-icon detect-icon-{sevCls}'>{IconFor(res.Severity)}</div>");
        sb.AppendLine($"            <div class='detect-tag {statusCls}'>{Esc(statusTag)}</div>");
        sb.AppendLine("          </div>");
        sb.AppendLine($"          <div class='detect-title'>{Esc(res.Title)}</div>");
        if (extras.Count > 0)
            sb.AppendLine($"          <div class='detect-multi'>+ {extras.Count} more source(s) — see details</div>");
        if (!string.IsNullOrEmpty(res.FilePath))
        {
            sb.AppendLine("          <div class='detect-path-row'>");
            sb.AppendLine("            <span class='path-icon'>&#128193;</span>");
            sb.AppendLine($"            <code class='path'>{Esc(res.FilePath)}</code>");
            sb.AppendLine("          </div>");
        }
        AppendShowDetails(sb, sec, res, extras);
        sb.AppendLine("        </div>");
    }

    private static void AppendDetectRow(StringBuilder sb,
        SessionReport.Section sec, ScanResult res,
        List<(SessionReport.Section Section, ScanResult Result)> extras)
    {
        bool active = IsActive(res) || extras.Any(x => IsActive(x.Result));
        var status     = res.Severity == Severity.Ok      ? "PASSED"
                       : res.Severity == Severity.Info    ? (active ? "ACTIVE" : "INACTIVE")
                       : res.Severity == Severity.Warn    ? "WARNING"
                       : res.Severity == Severity.Error   ? "ERROR"
                       : "BACKSTAGE";
        var statusTag  = active ? "Boot instance" : "Out of instance";
        var statusCls  = active ? "tag-active" : "tag-inactive";
        var sevCls     = "sev-" + res.Severity.ToString().ToLowerInvariant();

        // v0.8.0: row layout no longer carries the StatusBlurb fluff
        // ("Worth a closer look during the screenshare." etc.) — staff already
        // know what each severity means, the words are pure decoration.
        sb.AppendLine($"        <div class='detect-row {sevCls}'>");
        sb.AppendLine($"          <div class='row-icon row-icon-{sevCls}'>{IconFor(res.Severity)}</div>");
        sb.AppendLine("          <div class='row-info'>");
        sb.AppendLine($"            <div class='row-status'>{Esc(status)}</div>");
        sb.AppendLine($"            <div class='row-title'>{Esc(res.Title)}</div>");
        if (extras.Count > 0)
            sb.AppendLine($"            <div class='row-multi'>+ {extras.Count} more source(s) — see details</div>");
        if (!string.IsNullOrEmpty(res.FilePath))
            sb.AppendLine($"            <div class='row-path'><span class='path-icon'>&#128193;</span><code class='path'>{Esc(res.FilePath)}</code></div>");
        sb.AppendLine("          </div>");
        sb.AppendLine("          <div class='row-actions'>");
        sb.AppendLine($"            <span class='detect-tag {statusCls}'>{Esc(statusTag)}</span>");
        sb.AppendLine("          </div>");
        AppendShowDetails(sb, sec, res, extras);
        sb.AppendLine("        </div>");
    }

    private static void AppendShowDetails(StringBuilder sb,
        SessionReport.Section sec, ScanResult res,
        List<(SessionReport.Section Section, ScanResult Result)> extras)
    {
        // Only render if there's something extra to show.
        bool hasMore = !string.IsNullOrEmpty(res.Detail)
                    || !string.IsNullOrEmpty(res.Hash)
                    || (res.Tags is { Count: > 0 })
                    || res.Timestamp.HasValue
                    || !string.IsNullOrEmpty(res.Source)
                    || extras.Count > 0;
        if (!hasMore) return;

        sb.AppendLine("          <details class='show-details'>");
        sb.AppendLine("            <summary>Show details</summary>");
        sb.AppendLine("            <div class='details-body'>");
        sb.AppendLine($"              <div class='details-meta'>");
        sb.AppendLine($"                <span><b>Source:</b> {Esc(res.Source)}</span>");
        sb.AppendLine($"                <span><b>Section:</b> {Esc(sec.Title)}</span>");
        sb.AppendLine($"                <span><b>Severity:</b> {Esc(res.Severity.ToString().ToUpperInvariant())}</span>");
        if (res.Timestamp.HasValue)
            sb.AppendLine($"                <span><b>Time:</b> {res.Timestamp:yyyy-MM-dd HH:mm:ss}</span>");
        sb.AppendLine("              </div>");
        if (!string.IsNullOrEmpty(res.Hash))
            sb.AppendLine($"              <div class='details-hash'><b>Hash:</b> <code>{Esc(res.Hash)}</code></div>");
        if (res.Tags is { Count: > 0 })
        {
            sb.Append("              <div class='details-tags'>");
            foreach (var t in res.Tags) sb.Append($"<span class='tag'>{Esc(t)}</span> ");
            sb.AppendLine("</div>");
        }
        if (!string.IsNullOrEmpty(res.Detail))
            sb.AppendLine($"              <pre class='details-detail'>{Esc(res.Detail)}</pre>");

        if (extras.Count > 0)
        {
            sb.AppendLine("              <div class='details-extras'>");
            sb.AppendLine("                <b>Other source(s) reporting this same finding:</b>");
            sb.AppendLine("                <ul>");
            foreach (var (xSec, xRes) in extras)
            {
                var line = $"<b>{Esc(xRes.Source)}</b> · <span class='dim'>{Esc(xSec.Title)}</span> · {Esc(xRes.Title)}";
                if (!string.IsNullOrEmpty(xRes.FilePath))
                    line += $" · <code class='path'>{Esc(xRes.FilePath)}</code>";
                sb.AppendLine($"                  <li>{line}</li>");
            }
            sb.AppendLine("                </ul>");
            sb.AppendLine("              </div>");
        }

        sb.AppendLine("            </div>");
        sb.AppendLine("          </details>");
    }

    private static bool IsActive(ScanResult r)
    {
        if (r.Tags is { Count: > 0 } && r.Tags.Any(t => string.Equals(t, "active", StringComparison.OrdinalIgnoreCase)))
            return true;
        // ProcessScanner findings are by definition "currently running".
        if (string.Equals(r.Source, "ProcessScanner", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    private static string IconFor(Severity sev) => sev switch
    {
        Severity.Hit   => "&#9888;",   // ⚠ warning sign
        Severity.Warn  => "&#9888;",
        Severity.Info  => "&#128229;", // 📥 inbox-tray (info)
        Severity.Ok    => "&#10003;",  // ✓ check mark
        Severity.Error => "&#10006;",  // ✖ cross
        _              => "&#9679;",
    };

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "…";

    /// <summary>Severity ranking used for picking the "primary" finding in a dedup group.</summary>
    private static int SevRank(Severity s) => s switch
    {
        Severity.Hit   => 5,
        Severity.Warn  => 4,
        Severity.Error => 3,
        Severity.Info  => 2,
        Severity.Ok    => 1,
        _              => 0,
    };

    /// <summary>
    /// Tags used by scanners to annotate behaviour rather than identify a
    /// specific cheat client. We exclude these when computing the dedup key
    /// so a result tagged <c>["koid", "recent-files"]</c> still groups with
    /// another tagged <c>["koid", "active"]</c>.
    /// </summary>
    private static readonly HashSet<string> MetaTags = new(StringComparer.OrdinalIgnoreCase)
    {
        "active", "backstage", "recent-files",
        "engine", "selfdestruct", "bypass",
        "prefetch", "prefetch-missing", "event-log-cleared",
        "ads", "ads-script", "usn-summary",
    };

    /// <summary>
    /// Compute a stable dedup key for a finding. Findings sharing this key
    /// are merged into a single card whose "Show details" lists the other
    /// sources. Strategy: prefer the first non-meta <c>Tag</c> (the cheat
    /// keyword like <c>koid</c> / <c>atermys</c>); fall back to
    /// <c>Source|Title</c> for findings that have no keyword tags.
    /// </summary>
    private static string DedupeKey(ScanResult r)
    {
        if (r.Tags is { Count: > 0 })
        {
            foreach (var t in r.Tags)
            {
                if (string.IsNullOrEmpty(t)) continue;
                if (MetaTags.Contains(t)) continue;
                return "kw:" + t.ToLowerInvariant();
            }
        }
        return ("st:" + r.Source + "|" + r.Title).ToLowerInvariant();
    }

    // -----------------------------------------------------------------

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
        => $"    <li class='pc-row'><span class='dot dot-{dot}'></span><span class='pc-label'>{Esc(label)}</span><span class='pc-value'>{value}</span></li>";

    private static void RenderAccountsCards(StringBuilder sb, SessionReport r)
    {
        if (r.McAccounts.Count == 0
            && r.DiscordInstalls.Count == 0
            && r.DiscordAccounts.Count == 0) return;

        sb.AppendLine("<section class='cards-row'>");

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

        // v0.9.0: Discord card now shows the actual signed-in *accounts*
        // (username + ID + avatar), pulled from Discord's own
        // _remoteAuth_recentAccounts list. Falls back to "Discord
        // installations" when no accounts are pulled (e.g. user passed
        // --no-discord, or Discord just installed and never signed in).
        sb.AppendLine("  <div class='card half'>");
        sb.AppendLine("    <div class='card-head'>");
        sb.AppendLine("      <div class='discord-head'>");
        sb.AppendLine("        <span class='discord-ico'>&#128172;</span>");
        sb.AppendLine($"        <h3>Discord Accounts ({r.DiscordAccounts.Count})</h3>");
        sb.AppendLine("      </div>");
        sb.AppendLine("      <p class='card-sub'>Discord accounts detected on this system. We read only public fields (user ID, username, avatar) from the local-storage account list — never tokens, DMs, or chat messages.</p>");
        sb.AppendLine("    </div>");
        if (r.DiscordAccounts.Count == 0)
        {
            if (r.DiscordInstalls.Count == 0)
                sb.AppendLine("    <p class='empty'>Discord not installed.</p>");
            else
            {
                sb.AppendLine("    <p class='empty'>No signed-in Discord accounts found.</p>");
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
        }
        else
        {
            sb.AppendLine("    <ul class='dc-list'>");
            foreach (var a in r.DiscordAccounts)
            {
                var avatarUrl = a.AvatarHash != null
                    ? $"https://cdn.discordapp.com/avatars/{Esc(a.UserId)}/{Esc(a.AvatarHash)}.png?size=80"
                    : $"https://cdn.discordapp.com/embed/avatars/{(int.Parse(a.UserId.Substring(Math.Max(0, a.UserId.Length - 4))) % 5)}.png";
                var displayName = a.GlobalName ?? a.Username;
                var subUsername = a.GlobalName != null ? a.Username : null;

                sb.AppendLine("      <li class='dc-row'>");
                sb.AppendLine($"        <img class='dc-avatar' src='{avatarUrl}' alt='' loading='lazy' onerror=\"this.classList.add('dc-avatar-fallback');this.removeAttribute('src');\">");
                sb.AppendLine("        <div class='dc-info'>");
                sb.AppendLine("          <div class='dc-name-row'>");
                sb.AppendLine("            <span class='dc-presence'></span>");
                sb.AppendLine($"            <span class='dc-name'>{Esc(displayName)}</span>");
                if (subUsername != null)
                    sb.AppendLine($"            <span class='dc-username'>@{Esc(subUsername)}</span>");
                sb.AppendLine("          </div>");
                sb.AppendLine($"          <div class='dc-id'>ID: {Esc(a.UserId)}</div>");
                if (!string.Equals(a.ClientVariant, "Discord", StringComparison.Ordinal))
                    sb.AppendLine($"          <div class='dc-meta'><span class='tag'>{Esc(a.ClientVariant)}</span></div>");
                sb.AppendLine("        </div>");
                sb.AppendLine("        <div class='dc-actions'>");
                sb.AppendLine($"          <button type='button' class='dc-btn dc-btn-copy' data-copy='{Esc(a.UserId)}' title='Copy user ID'>&#128203;</button>");
                sb.AppendLine("        </div>");
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
            sb.AppendLine($"      <div class='mod-path'><span class='path-icon'>&#128193;</span><code class='path'>{Esc(m.FilePath)}</code></div>");
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

    private static string FormatDuration(TimeSpan ts)
    {
        if (ts.TotalSeconds < 1)         return $"{ts.TotalMilliseconds:0} ms";
        if (ts.TotalMinutes < 1)         return $"{ts.TotalSeconds:0.##} s";
        if (ts.TotalHours < 1)           return $"{(int)ts.TotalMinutes}m {ts.Seconds}s";
        return $"{(int)ts.TotalHours}h {ts.Minutes}m";
    }

    private static string Css() => @"
:root { color-scheme: light dark; --bg: #0e1116; --bg2: #131820; --bg3: #1a1f2b; --bd: #2a313e; --fg: #e6e6e6; --dim: #aaa; --link: #6cb6ff; --hit: #ff6c6c; --warn: #f5d97c; --ok: #6ce6a0; --info: #6cb6ff; }
* { box-sizing: border-box; }
body { font: 14px/1.45 -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 0; background: var(--bg); color: var(--fg); }

header.top { padding: 24px 32px; background: linear-gradient(180deg, #1a1f2b, #0e1116); border-bottom: 1px solid var(--bd); }
.top-row { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
header.top h1 { margin: 0 0 8px 0; font-size: 24px; }
.export-btn { display: inline-flex; align-items: center; gap: 8px; padding: 8px 16px; border-radius: 8px; border: 1px solid var(--bd); background: var(--bg3); color: var(--fg); font-size: 13px; font-weight: 600; cursor: pointer; transition: background 120ms, border-color 120ms, transform 80ms; }
.export-btn:hover { background: rgba(255,255,255,0.06); border-color: rgba(255,255,255,0.20); }
.export-btn:active { transform: translateY(1px); }
.export-btn .export-ico { font-size: 14px; }
.meta { display: flex; flex-wrap: wrap; gap: 12px 24px; font-size: 13px; color: var(--dim); }
.meta span b { color: #ddd; font-weight: 600; }
.verdict { display: block; margin-top: 16px; padding: 16px 22px; border-radius: 10px; font-weight: 500; font-size: 17px; text-align: center; border: 1px solid transparent; }
.verdict b { font-weight: 800; }
.verdict-sub { font-weight: 400; color: inherit; opacity: 0.7; font-size: 14px; margin-left: 6px; }
.verdict-clean { background: rgba(108, 230, 160, 0.10); color: #6ce6a0; border-color: rgba(108, 230, 160, 0.25); }
.verdict-clean b { color: #6ce6a0; }
.verdict-warn  { background: rgba(245, 217, 124, 0.10); color: #f5d97c; border-color: rgba(245, 217, 124, 0.25); }
.verdict-warn b { color: #f5d97c; }
.verdict-hit   { background: rgba(255, 80, 80, 0.10);   color: #ffb3b3; border-color: rgba(255, 80, 80, 0.30); }
.verdict-hit b { color: #ff6c6c; }
.disclaimer { margin-top: 12px; color: var(--dim); font-size: 12px; }

.card { margin: 18px 32px; background: var(--bg2); border: 1px solid var(--bd); border-radius: 12px; padding: 22px 26px; }
.card.half { flex: 1 1 0; min-width: 0; }
.cards-row { display: flex; gap: 16px; margin: 18px 32px; }
.card-head h2, .card-head h3 { margin: 0 0 4px 0; font-size: 18px; }
.card-head .card-sub { margin: 0 0 14px 0; color: var(--dim); font-size: 12px; }

/* ----- Tab navigation ----- */
.cat-radio { position: absolute; opacity: 0; pointer-events: none; }
.cat-tabs { display: flex; gap: 6px; border-bottom: 1px solid var(--bd); margin-bottom: 18px; flex-wrap: wrap; }
.cat-tab { display: inline-flex; align-items: center; gap: 8px; padding: 10px 16px; border-radius: 8px 8px 0 0; cursor: pointer; user-select: none; color: var(--dim); border: 1px solid transparent; border-bottom: none; transition: background 120ms; }
.cat-tab .tab-label { font-size: 13px; font-weight: 600; }
.cat-tab .tab-count { background: rgba(255,255,255,0.06); padding: 1px 8px; border-radius: 999px; font-size: 11px; font-family: ui-monospace, monospace; min-width: 22px; text-align: center; }
.cat-tab:hover { background: rgba(255,255,255,0.04); color: var(--fg); }

/* Highlight active tab via :checked sibling. */
#cat-detects:checked    ~ .cat-tabs .cat-tab[for=cat-detects],
#cat-integrity:checked  ~ .cat-tabs .cat-tab[for=cat-integrity],
#cat-warnings:checked   ~ .cat-tabs .cat-tab[for=cat-warnings],
#cat-suspicious:checked ~ .cat-tabs .cat-tab[for=cat-suspicious],
#cat-backstage:checked  ~ .cat-tabs .cat-tab[for=cat-backstage] {
  color: var(--fg);
  background: var(--bg3);
  border-color: var(--bd);
  position: relative;
}
#cat-detects:checked    ~ .cat-tabs .cat-tab[for=cat-detects]    .tab-count { color: #ffb3b3; background: rgba(255, 80, 80, 0.18); }
#cat-integrity:checked  ~ .cat-tabs .cat-tab[for=cat-integrity]  .tab-count { color: #b3f0c1; background: rgba(120, 220, 120, 0.16); }
#cat-warnings:checked   ~ .cat-tabs .cat-tab[for=cat-warnings]   .tab-count { color: #f5d97c; background: rgba(245, 217, 124, 0.18); }
#cat-suspicious:checked ~ .cat-tabs .cat-tab[for=cat-suspicious] .tab-count { color: #a3c4e6; background: rgba(120, 170, 240, 0.16); }
#cat-backstage:checked  ~ .cat-tabs .cat-tab[for=cat-backstage]  .tab-count { color: #cdb1f2; background: rgba(180, 130, 240, 0.16); }

/* Panes default to hidden; the matching :checked radio reveals one. */
.cat-panes { display: block; }
.pane { display: none; }
#cat-detects:checked    ~ .cat-panes .pane-detects    { display: block; }
#cat-integrity:checked  ~ .cat-panes .pane-integrity  { display: block; }
#cat-warnings:checked   ~ .cat-panes .pane-warnings   { display: block; }
#cat-suspicious:checked ~ .cat-panes .pane-suspicious { display: block; }
#cat-backstage:checked  ~ .cat-panes .pane-backstage  { display: block; }

.pane-head h3 { margin: 0 0 4px 0; font-size: 16px; display: flex; align-items: center; gap: 8px; }

/* ----- Detect cards (headline grid) ----- */
.detect-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 14px; margin-bottom: 18px; }
.detect-card { background: var(--bg3); border: 1px solid var(--bd); border-left: 4px solid var(--bd); border-radius: 10px; padding: 16px 18px; display: flex; flex-direction: column; gap: 10px; }
.detect-card.sev-hit  { border-left-color: var(--hit); }
.detect-card.sev-warn { border-left-color: var(--warn); }
.detect-card.sev-info { border-left-color: var(--info); }
.detect-card.sev-ok   { border-left-color: var(--ok); }

.detect-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.detect-icon { width: 44px; height: 44px; border-radius: 10px; background: rgba(255,255,255,0.04); border: 1px solid var(--bd); display: flex; align-items: center; justify-content: center; font-size: 20px; }
.detect-icon.detect-icon-sev-hit  { color: var(--hit); border-color: rgba(255, 80, 80, 0.3); }
.detect-icon.detect-icon-sev-warn { color: var(--warn); border-color: rgba(245, 217, 124, 0.3); }
.detect-icon.detect-icon-sev-info { color: var(--info); border-color: rgba(120, 170, 240, 0.3); }
.detect-icon.detect-icon-sev-ok   { color: var(--ok); border-color: rgba(120, 220, 120, 0.3); }

.detect-tag { font-size: 12px; font-weight: 600; padding: 4px 10px; border-radius: 6px; border: 1px solid transparent; }
.detect-tag.tag-active   { color: var(--hit); border-color: rgba(255, 80, 80, 0.45); background: rgba(255, 80, 80, 0.10); }
.detect-tag.tag-inactive { color: var(--dim); border-color: var(--bd);              background: rgba(255,255,255,0.04); }

.detect-title { font-size: 16px; font-weight: 700; line-height: 1.3; }
.detect-multi, .row-multi { color: var(--dim); font-size: 12px; font-style: italic; }
.detect-path-row { display: flex; align-items: center; gap: 8px; font-size: 12px; }
.path-icon { font-size: 14px; opacity: 0.7; }

/* ----- Detect rows (compact) ----- */
.detect-rows { display: flex; flex-direction: column; gap: 8px; }
.detect-row { display: flex; align-items: flex-start; gap: 14px; padding: 14px 16px; background: var(--bg3); border: 1px solid var(--bd); border-radius: 10px; flex-wrap: wrap; }
.row-icon { width: 36px; height: 36px; border-radius: 8px; background: rgba(255,255,255,0.04); border: 1px solid var(--bd); display: flex; align-items: center; justify-content: center; font-size: 16px; flex: 0 0 auto; }
.row-icon-sev-hit  { color: var(--hit); }
.row-icon-sev-warn { color: var(--warn); }
.row-icon-sev-info { color: var(--info); }
.row-icon-sev-ok   { color: var(--ok); }
.row-info { flex: 1 1 320px; min-width: 0; }
.row-status { font-size: 11px; font-weight: 700; letter-spacing: 0.6px; color: var(--dim); }
.row-meta { font-size: 12px; color: var(--dim); margin-top: 2px; }
.row-title { font-size: 14px; font-weight: 600; margin-top: 6px; }
.row-path { font-size: 12px; margin-top: 6px; display: flex; align-items: center; gap: 6px; }
.row-actions { display: flex; align-items: center; gap: 8px; margin-left: auto; flex: 0 0 auto; }

.show-details { width: 100%; margin-top: 6px; border-top: 1px dashed var(--bd); padding-top: 8px; }
.show-details summary { cursor: pointer; font-size: 12px; color: var(--link); user-select: none; }
.show-details summary::marker { color: var(--link); }
.details-body { margin-top: 8px; font-size: 12px; }
.details-meta { display: flex; flex-wrap: wrap; gap: 6px 16px; color: var(--dim); margin-bottom: 6px; }
.details-meta b { color: #ddd; }
.details-hash { margin-bottom: 6px; }
.details-tags { margin-bottom: 6px; }
.details-detail { font-family: ui-monospace, monospace; font-size: 11px; white-space: pre-wrap; word-break: break-word; background: var(--bg2); padding: 8px 10px; border-radius: 6px; max-height: 240px; overflow: auto; }
.details-extras { margin-top: 8px; padding-top: 8px; border-top: 1px dashed var(--bd); }
.details-extras ul { margin: 6px 0 0 0; padding-left: 18px; }
.details-extras li { margin: 4px 0; word-break: break-word; }

/* ----- PC info / accounts / mods ----- */
.pc-list { list-style: none; margin: 0; padding: 0; }
.pc-row { display: flex; align-items: center; gap: 12px; padding: 10px 0; border-bottom: 1px dashed var(--bd); }
.pc-row:last-child { border-bottom: none; }
.pc-label { color: var(--dim); flex: 1 1 0; }
.pc-value { font-weight: 600; text-align: right; }
.pc-row.pc-hw .pc-value { font-weight: 400; color: var(--dim); font-size: 12px; }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex: 0 0 auto; }
.dot-system { background: #6cb6ff; }
.dot-boot { background: #6ce6a0; }
.dot-vpn-no { background: #ff6c6c; }
.dot-vpn-yes { background: #ff9d3a; }
.dot-install { background: #b18cf2; }
.dot-country { background: #ff9d3a; }
.dot-game { background: #6ce6a0; }
.dot-recycle { background: #ff9d3a; }
.dot-discord { background: #5865f2; }
.dot-hw { background: #6cb6ff; }

.acc-list { list-style: none; margin: 0; padding: 0; }
.acc-row { padding: 10px 12px; margin: 6px 0; background: var(--bg3); border: 1px solid var(--bd); border-radius: 8px; }
.acc-name { font-family: ui-monospace, monospace; font-weight: 700; }
.acc-meta { margin-top: 4px; font-size: 12px; color: var(--dim); }
.tag { display: inline-block; padding: 1px 6px; border-radius: 3px; background: var(--bd); color: #c0c0c0; font-size: 11px; font-family: ui-monospace, monospace; }
.tag-run { background: #1d3823; color: #b3f0c1; }

/* ----- Discord-account list ----- */
.discord-head { display: flex; align-items: center; gap: 8px; }
.discord-head h3 { margin: 0; }
.discord-ico { font-size: 20px; }
.dc-list { list-style: none; margin: 0; padding: 0; }
.dc-row { display: flex; align-items: center; gap: 14px; padding: 12px 14px; margin: 8px 0; background: var(--bg3); border: 1px solid var(--bd); border-radius: 10px; }
.dc-avatar { width: 40px; height: 40px; border-radius: 50%; background: var(--bd); object-fit: cover; flex: 0 0 auto; }
.dc-avatar.dc-avatar-fallback { background: linear-gradient(135deg, #5865f2, #404eed); }
.dc-info { flex: 1 1 0; min-width: 0; }
.dc-name-row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.dc-presence { width: 10px; height: 10px; border-radius: 50%; background: #43b581; box-shadow: 0 0 0 2px var(--bg3); flex: 0 0 auto; }
.dc-name { font-weight: 700; font-size: 14px; color: var(--fg); }
.dc-username { color: var(--dim); font-size: 12px; }
.dc-id { font-family: ui-monospace, monospace; font-size: 12px; color: var(--dim); margin-top: 2px; }
.dc-id::before { content: ''; }
.dc-meta { margin-top: 4px; font-size: 11px; }
.dc-actions { display: flex; align-items: center; gap: 6px; flex: 0 0 auto; }
.dc-btn { width: 32px; height: 32px; border-radius: 8px; border: 1px solid var(--bd); background: transparent; color: var(--dim); cursor: pointer; font-size: 14px; display: inline-flex; align-items: center; justify-content: center; transition: background 120ms, color 120ms, border-color 120ms; }
.dc-btn:hover { background: rgba(255,255,255,0.05); color: var(--fg); border-color: rgba(255,255,255,0.20); }

.mods-list { list-style: none; margin: 0; padding: 0; }
.mod-row { padding: 12px 14px; margin: 8px 0; background: var(--bg3); border: 1px solid var(--bd); border-radius: 8px; border-left: 4px solid var(--bd); }
.mod-row.ver-yes     { border-left-color: var(--ok); }
.mod-row.ver-no      { border-left-color: #ff9d3a; }
.mod-row.ver-skip,
.mod-row.ver-unknown { border-left-color: #888; }
.mod-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.mod-name { font-family: ui-monospace, monospace; font-weight: 700; flex: 1 1 auto; min-width: 0; word-break: break-all; }
.mod-badge { font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px; }
.mod-badge.ver-yes     { background: rgba(120, 220, 120, 0.12); color: #b3f0c1; }
.mod-badge.ver-no      { background: rgba(255, 158, 60, 0.18);  color: #ffd09d; }
.mod-badge.ver-skip,
.mod-badge.ver-unknown { background: rgba(255,255,255,0.06); color: #aaa; }
.mod-size { font-size: 12px; color: var(--dim); font-family: ui-monospace, monospace; }
.mod-meta { margin-top: 6px; }
.mod-link { margin-top: 6px; font-size: 12px; word-break: break-all; }
.mod-link a { color: var(--link); }
.mod-path { margin-top: 6px; display: flex; gap: 6px; align-items: center; }

/* ----- Raw scanner sections (collapsed by default) ----- */
.raw-toggle { margin: 18px 32px; }
.raw-toggle > summary { cursor: pointer; padding: 12px 18px; background: var(--bg2); border: 1px solid var(--bd); border-radius: 8px; font-weight: 600; color: var(--dim); }
.raw-toggle[open] > summary { border-bottom-left-radius: 0; border-bottom-right-radius: 0; }

/* ----- Severity filter bar (raw sections) ----- */
.sev-filter { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; padding: 12px 32px; background: var(--bg2); border-left: 1px solid var(--bd); border-right: 1px solid var(--bd); }
.sev-filter-label { color: var(--dim); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-right: 4px; }
.sev-btn { cursor: pointer; user-select: none; font: 600 12px/1 ui-monospace, monospace; padding: 6px 12px; border-radius: 999px; border: 1px solid var(--bd); background: var(--bg3); color: var(--dim); transition: background 120ms, color 120ms, border-color 120ms; }
.sev-btn:hover { color: var(--fg); }
.sev-btn.active { color: var(--fg); }
.sev-btn-all.active  { background: rgba(255,255,255,0.10); border-color: rgba(255,255,255,0.30); }
.sev-btn-hit.active  { background: rgba(255, 80, 80, 0.18);  border-color: rgba(255, 80, 80, 0.55);  color: #ffb3b3; }
.sev-btn-warn.active { background: rgba(245, 217, 124, 0.18); border-color: rgba(245, 217, 124, 0.55); color: #f5d97c; }
.sev-btn-ok.active   { background: rgba(120, 220, 120, 0.16); border-color: rgba(120, 220, 120, 0.55); color: #b3f0c1; }
.sev-btn-info.active { background: rgba(120, 170, 240, 0.16); border-color: rgba(120, 170, 240, 0.55); color: #a3c4e6; }
.sev-btn-err.active  { background: rgba(255,255,255,0.08);   border-color: rgba(255,255,255,0.25);   color: #ddd; }
nav.toc { padding: 16px 32px; background: var(--bg2); border-left: 1px solid var(--bd); border-right: 1px solid var(--bd); }
nav.toc h2 { margin: 0 0 8px 0; font-size: 14px; color: var(--dim); text-transform: uppercase; letter-spacing: 1px; }
nav.toc ol { margin: 0; padding-left: 24px; }
nav.toc a { color: var(--link); text-decoration: none; }
nav.toc a:hover { text-decoration: underline; }
section.sec { padding: 20px 32px; border-bottom: 1px solid #1f2630; background: var(--bg2); border-left: 1px solid var(--bd); border-right: 1px solid var(--bd); }
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
code.path { font-family: ui-monospace, monospace; font-size: 12px; background: var(--bg2); padding: 2px 6px; border-radius: 3px; word-break: break-all; }
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
  .cards-row { flex-direction: column; }
  .detect-grid { grid-template-columns: 1fr; }
  .row-actions { margin-left: 0; }
}
@media (prefers-color-scheme: light) {
  :root { --bg: #f7f8fa; --bg2: #ffffff; --bg3: #eef0f4; --bd: #e2e6ee; --fg: #222; --dim: #555; --link: #1759c4; --hit: #c2293a; --warn: #b48214; --ok: #1f8744; --info: #1759c4; }
  body { background: var(--bg); color: var(--fg); }
  header.top { background: linear-gradient(180deg, #fff, #f0f2f6); border-bottom-color: #ddd; }
  .meta span b { color: #222; }
  .verdict-clean { background: #def6e3; color: #176d2c; }
  .verdict-warn  { background: #fbeec1; color: #7a5a03; }
  .verdict-hit   { background: #fbd3d3; color: #b80b0b; }
  .cat-tab .tab-count { background: rgba(0,0,0,0.06); }
  .detect-card, .detect-row, .acc-row, .mod-row, code.path { background: var(--bg3); border-color: var(--bd); }
  .detect-icon, .row-icon { background: rgba(0,0,0,0.03); }
  .details-detail { background: rgba(0,0,0,0.03); }
  .detect-tag.tag-active   { color: var(--hit); border-color: rgba(194, 41, 58, 0.45); background: rgba(194, 41, 58, 0.06); }
  .detect-tag.tag-inactive { color: var(--dim); border-color: var(--bd);              background: rgba(0,0,0,0.03); }
  .mod-badge.ver-yes { background: #def6e3; color: #176d2c; }
  .mod-badge.ver-no  { background: #fde0c1; color: #8a4a00; }
  .tag-run { background: #def6e3; color: #176d2c; }
  pre.detail { background: var(--bg3); }
  .raw-toggle > summary { background: var(--bg2); }
  nav.toc, section.sec { background: var(--bg2); }
}
";
}
