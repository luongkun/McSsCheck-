using System;
using System.Collections.Generic;
using System.Linq;

namespace McSsCheck.Models;

/// <summary>
/// Container collecting <see cref="ScanResult"/> entries grouped by scanner section,
/// plus session metadata that the renderers (console + HTML) display in the report header.
/// </summary>
public sealed class SessionReport
{
    public string Hostname { get; init; } = Environment.MachineName;
    public string Username { get; init; } = Environment.UserName;
    public string OsVersion { get; init; } = Environment.OSVersion.ToString();
    public string ToolVersion { get; init; } = "0.2.0";
    public DateTime StartedAt { get; init; } = DateTime.Now;
    public DateTime? FinishedAt { get; set; }

    private readonly List<Section> _sections = new();
    public IReadOnlyList<Section> Sections => _sections;

    public Section StartSection(string title)
    {
        var s = new Section(title);
        _sections.Add(s);
        return s;
    }

    public int TotalHits => _sections.Sum(s => s.Hits);

    public sealed class Section
    {
        public string Title { get; }
        private readonly List<ScanResult> _results = new();
        public IReadOnlyList<ScanResult> Results => _results;

        public Section(string title) { Title = title; }

        public void Add(ScanResult r) => _results.Add(r);

        public int Hits => _results.Count(r => r.Severity == Severity.Hit);
        public int Warnings => _results.Count(r => r.Severity == Severity.Warn);
    }
}
