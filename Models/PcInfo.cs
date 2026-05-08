using System;
using System.Collections.Generic;

namespace McSsCheck.Models;

/// <summary>
/// "PC Information" panel that gets rendered at the top of the HTML report.
/// Everything here is plain WMI / registry / environment lookups — no
/// network, no privileged calls. Any field that can't be determined is
/// left null and the renderer simply hides it.
/// </summary>
public sealed class PcInfo
{
    public string? System         { get; set; }   // e.g. "Windows 11 Pro 25H2 (10.0.26200)"
    public DateTime? BootTime     { get; set; }
    public DateTime? InstallDate  { get; set; }
    public string? Country        { get; set; }   // e.g. "Vietnam (vi-VN)"
    public string? TimeZone       { get; set; }
    public DateTime? LastGameTime { get; set; }   // last javaw/minecraft prefetch mtime
    public DateTime? LastRecycle  { get; set; }   // newest mtime under any $Recycle.Bin

    public string? Cpu            { get; set; }
    public string? Gpu            { get; set; }
    public long? RamBytes         { get; set; }
    public List<DiskInfo> Disks   { get; } = new();

    public string? VpnStatus      { get; set; }   // "no", "possible (TAP-Windows adapter)", etc.
    public List<string> VpnHits   { get; } = new();

    public string? DiscordInstall { get; set; }   // null = not installed; otherwise a friendly version string

    public sealed class DiskInfo
    {
        public string Name    { get; set; } = "";   // e.g. "C:"
        public string? Model  { get; set; }         // from Win32_DiskDrive (best-effort)
        public long?  Size    { get; set; }
        public long?  Free    { get; set; }
        public string? Format { get; set; }         // NTFS / FAT32 / ...
    }
}
