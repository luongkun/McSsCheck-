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
    /// <summary>
    /// Filled by <see cref="Program"/> at startup from the assembly's
    /// InformationalVersion. Kept as a writable property so renderers can
    /// display whatever the running binary actually is, no string duplication.
    /// </summary>
    public string ToolVersion { get; set; } = "0.0.0";
    public DateTime StartedAt { get; init; } = DateTime.Now;
    public DateTime? FinishedAt { get; set; }

    /// <summary>Optional PC information panel data (filled by <c>SystemInfoScanner</c>).</summary>
    public PcInfo? Pc { get; set; }

    /// <summary>Alternative Minecraft accounts discovered on disk.</summary>
    public List<MinecraftAccount> McAccounts { get; } = new();

    /// <summary>Discord client installations (presence only — no chat / token data).</summary>
    public List<DiscordInstall> DiscordInstalls { get; } = new();

    /// <summary>Mod jars discovered under .minecraft/mods (and versions/) with optional registry verification.</summary>
    public List<ModEntry> Mods { get; } = new();

    private readonly List<Section> _sections = new();
    public IReadOnlyList<Section> Sections => _sections;

    public Section StartSection(string title)
    {
        var s = new Section(title);
        _sections.Add(s);
        return s;
    }

    public int TotalHits => _sections.Sum(s => s.Hits);

    /// <summary>Counts of Detects / Integrity / Warnings / Suspicious / Backstage rows across all sections.</summary>
    public CategoryCounts Counts()
    {
        int detects = 0, integrity = 0, warnings = 0, suspicious = 0, backstage = 0, errors = 0;
        foreach (var sec in _sections)
        {
            foreach (var r in sec.Results)
            {
                switch (Categorize(r))
                {
                    case ResultCategory.Detects:    detects++;    break;
                    case ResultCategory.Integrity:  integrity++;  break;
                    case ResultCategory.Warnings:   warnings++;   break;
                    case ResultCategory.Suspicious: suspicious++; break;
                    case ResultCategory.Backstage:  backstage++;  break;
                    case ResultCategory.Errors:     errors++;     break;
                }
            }
        }
        return new CategoryCounts(detects, integrity, warnings, suspicious, backstage, errors);
    }

    /// <summary>
    /// Classify a single result into one of the Ocean-style buckets.
    /// HIT → Detects, OK → Integrity, WARN → Warnings, INFO → Suspicious by default,
    /// ERROR → Errors. INFO entries explicitly tagged "backstage" go to Backstage.
    /// </summary>
    public static ResultCategory Categorize(ScanResult r)
    {
        if (r.Tags is { Count: > 0 })
        {
            foreach (var t in r.Tags)
                if (string.Equals(t, "backstage", StringComparison.OrdinalIgnoreCase))
                    return ResultCategory.Backstage;
        }
        return r.Severity switch
        {
            Severity.Hit   => ResultCategory.Detects,
            Severity.Ok    => ResultCategory.Integrity,
            Severity.Warn  => ResultCategory.Warnings,
            Severity.Info  => ResultCategory.Suspicious,
            Severity.Error => ResultCategory.Errors,
            _              => ResultCategory.Suspicious,
        };
    }

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

public enum ResultCategory { Detects, Integrity, Warnings, Suspicious, Backstage, Errors }

public sealed record CategoryCounts(
    int Detects,
    int Integrity,
    int Warnings,
    int Suspicious,
    int Backstage,
    int Errors)
{
    public int Total => Detects + Integrity + Warnings + Suspicious + Backstage + Errors;
}
