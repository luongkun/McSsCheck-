namespace McSsCheck.Models;

/// <summary>
/// All the per-section opt-out flags + global config (VT key, html path),
/// passed from <see cref="Program"/> argument parsing into the host (console
/// or GUI) and ultimately into <see cref="ScanOrchestrator"/>.
/// </summary>
internal sealed record ScanOptions
{
    public bool NoBrowser   { get; init; }
    public bool NoRecycle   { get; init; }
    public bool NoRegistry  { get; init; }
    public bool NoPrefetch  { get; init; }
    public bool NoUsn       { get; init; }
    public bool NoDefender  { get; init; }
    public bool NoVt        { get; init; }
    public bool NoHtml      { get; init; }
    public bool NoPcInfo    { get; init; }
    public bool NoAccounts  { get; init; }
    public bool NoModrinth  { get; init; }
    public bool NoLiveJvm   { get; init; }
    public bool NoEngines   { get; init; }
    public bool NoStartup   { get; init; }
    public bool NoTasks     { get; init; }
    public bool NoRecent    { get; init; }
    public string? VtKey       { get; init; }
    public string? HtmlPathArg { get; init; }
}
