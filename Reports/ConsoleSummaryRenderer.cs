using System.Linq;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Reports;

internal static class ConsoleSummaryRenderer
{
    public static void Render(SessionReport report)
    {
        ConsoleUI.Section("Session summary");

        int totalHits  = report.Sections.Sum(s => s.Hits);
        int totalWarns = report.Sections.Sum(s => s.Warnings);
        int totalInfos = report.Sections.Sum(s => s.Results.Count(r => r.Severity == Severity.Info));
        int totalErrs  = report.Sections.Sum(s => s.Results.Count(r => r.Severity == Severity.Error));

        foreach (var s in report.Sections)
            ConsoleUI.Info($"  {s.Title,-50}  hits={s.Hits,-3}  warns={s.Warnings,-3}  total={s.Results.Count}");

        ConsoleUI.Info("");
        ConsoleUI.Info($"Totals: HIT={totalHits}  WARN={totalWarns}  INFO={totalInfos}  ERR={totalErrs}");

        if (totalHits == 0 && totalWarns == 0)
            ConsoleUI.Ok("No hits and no warnings. Nothing automatically suspicious found in scanned scopes.");
        else if (totalHits == 0)
            ConsoleUI.Warn($"{totalWarns} warning(s). Worth a manual look during the SS session.");
        else
            ConsoleUI.Hit($"{totalHits} hit(s). Each one should be reviewed manually before drawing any conclusion.");
    }
}
