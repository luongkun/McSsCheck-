using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.Versioning;
using McSsCheck.Models;
using McSsCheck.Util;
using Microsoft.Win32;

namespace McSsCheck.Scanners;

/// <summary>
/// Populates <see cref="SessionReport.Pc"/> with PC information that the HTML
/// report shows in the top "PC Information" panel: OS version, boot time,
/// install date, locale/country, hardware (CPU/GPU/RAM/disks), last game
/// launch, last Recycle-Bin activity, VPN heuristic, Discord install
/// presence.
///
/// Everything is read-only and local: WMI / registry / environment. No
/// network. No leveldb / token / chat data is touched.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class SystemInfoScanner
{
    public const string SourceName = "SystemInfoScanner";

    public static void Run(SessionReport report, SessionReport.Section section)
    {
        ConsoleUI.Section("PC information");
        var pc = new PcInfo();
        report.Pc = pc;

        FillSystem(pc);
        FillLocale(pc);
        FillHardware(pc);
        FillDisks(pc);
        FillBootAndInstallDate(pc);
        FillLastGameTime(pc);
        FillLastRecycleTime(pc);
        FillVpn(pc);
        FillDiscord(report, pc);

        // Echo to the section so it also appears in the structured report.
        section.Add(new ScanResult(SourceName, Severity.Info,
            "PC: " + (pc.System ?? "unknown system"),
            BuildSummary(pc)));

        // Friendly console echo
        if (pc.System         != null) ConsoleUI.Info($"  System       : {pc.System}");
        if (pc.BootTime       != null) ConsoleUI.Info($"  Boot time    : {pc.BootTime:yyyy-MM-dd HH:mm:ss} ({Ago(pc.BootTime.Value)})");
        if (pc.InstallDate    != null) ConsoleUI.Info($"  Install date : {pc.InstallDate:yyyy-MM-dd HH:mm:ss}");
        if (pc.Country        != null) ConsoleUI.Info($"  Country      : {pc.Country}");
        if (pc.TimeZone       != null) ConsoleUI.Info($"  Time zone    : {pc.TimeZone}");
        if (pc.Cpu            != null) ConsoleUI.Info($"  CPU          : {pc.Cpu}");
        if (pc.Gpu            != null) ConsoleUI.Info($"  GPU          : {pc.Gpu}");
        if (pc.RamBytes       != null) ConsoleUI.Info($"  RAM          : {FormatBytes(pc.RamBytes.Value)}");
        foreach (var d in pc.Disks)
            ConsoleUI.Info($"  Disk {d.Name}      : {d.Format} {FormatBytes(d.Size ?? 0)} (free {FormatBytes(d.Free ?? 0)})");
        if (pc.LastGameTime   != null) ConsoleUI.Info($"  Last game    : {pc.LastGameTime:yyyy-MM-dd HH:mm:ss} ({Ago(pc.LastGameTime.Value)})");
        if (pc.LastRecycle    != null) ConsoleUI.Info($"  Last recycle : {pc.LastRecycle:yyyy-MM-dd HH:mm:ss} ({Ago(pc.LastRecycle.Value)})");
        if (pc.VpnStatus      != null) ConsoleUI.Info($"  VPN          : {pc.VpnStatus}");
        if (pc.DiscordInstall != null) ConsoleUI.Info($"  Discord      : {pc.DiscordInstall}");
        else                           ConsoleUI.Dim ("  Discord      : not installed");
    }

    // ---------------------------------------------------------------------

    private static void FillSystem(PcInfo pc)
    {
        try
        {
            using var s = new ManagementObjectSearcher(
                "SELECT Caption, Version, BuildNumber FROM Win32_OperatingSystem");
            foreach (ManagementObject o in s.Get())
            {
                var caption = o["Caption"]?.ToString()?.Trim();
                var version = o["Version"]?.ToString();
                var build   = o["BuildNumber"]?.ToString();

                var displayVersion = TryReadDisplayVersion();
                pc.System = $"{caption ?? "Windows"}{(displayVersion != null ? " " + displayVersion : "")} ({version}.{build})";
                break;
            }
        }
        catch (Exception ex)
        {
            pc.System = Environment.OSVersion.ToString();
            ConsoleUI.Dim($"  WMI Win32_OperatingSystem failed: {ex.Message}");
        }
    }

    private static string? TryReadDisplayVersion()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return k?.GetValue("DisplayVersion")?.ToString();
        }
        catch { return null; }
    }

    private static void FillLocale(PcInfo pc)
    {
        try
        {
            var c = CultureInfo.InstalledUICulture;
            var region = new RegionInfo(c.Name);
            pc.Country = $"{region.EnglishName} ({c.Name})";
        }
        catch { /* ignore */ }
        try { pc.TimeZone = TimeZoneInfo.Local.DisplayName; } catch { /* ignore */ }
    }

    private static void FillHardware(PcInfo pc)
    {
        try
        {
            using var s = new ManagementObjectSearcher("SELECT Name FROM Win32_Processor");
            foreach (ManagementObject o in s.Get())
            {
                pc.Cpu = o["Name"]?.ToString()?.Trim();
                break;
            }
        }
        catch (Exception ex) { ConsoleUI.Dim($"  WMI Win32_Processor failed: {ex.Message}"); }

        try
        {
            using var s = new ManagementObjectSearcher("SELECT Name FROM Win32_VideoController");
            var names = new List<string>();
            foreach (ManagementObject o in s.Get())
            {
                var n = o["Name"]?.ToString()?.Trim();
                if (!string.IsNullOrEmpty(n)) names.Add(n!);
            }
            if (names.Count > 0) pc.Gpu = string.Join(" + ", names);
        }
        catch (Exception ex) { ConsoleUI.Dim($"  WMI Win32_VideoController failed: {ex.Message}"); }

        try
        {
            using var s = new ManagementObjectSearcher("SELECT Capacity FROM Win32_PhysicalMemory");
            long total = 0;
            foreach (ManagementObject o in s.Get())
            {
                if (o["Capacity"] is { } cap && ulong.TryParse(cap.ToString(), out var c))
                    total += (long)c;
            }
            if (total > 0) pc.RamBytes = total;
        }
        catch (Exception ex) { ConsoleUI.Dim($"  WMI Win32_PhysicalMemory failed: {ex.Message}"); }
    }

    private static void FillDisks(PcInfo pc)
    {
        try
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                if (d.DriveType != DriveType.Fixed) continue;
                var info = new PcInfo.DiskInfo
                {
                    Name   = d.Name.TrimEnd('\\'),
                };
                try
                {
                    if (d.IsReady)
                    {
                        info.Size   = d.TotalSize;
                        info.Free   = d.AvailableFreeSpace;
                        info.Format = d.DriveFormat;
                    }
                }
                catch { /* drive not ready */ }
                pc.Disks.Add(info);
            }
        }
        catch (Exception ex) { ConsoleUI.Dim($"  DriveInfo enumeration failed: {ex.Message}"); }
    }

    private static void FillBootAndInstallDate(PcInfo pc)
    {
        try
        {
            using var s = new ManagementObjectSearcher(
                "SELECT LastBootUpTime, InstallDate FROM Win32_OperatingSystem");
            foreach (ManagementObject o in s.Get())
            {
                if (o["LastBootUpTime"] is string b && !string.IsNullOrEmpty(b))
                    pc.BootTime = ManagementDateTimeConverter.ToDateTime(b);
                if (o["InstallDate"] is string i && !string.IsNullOrEmpty(i))
                    pc.InstallDate = ManagementDateTimeConverter.ToDateTime(i);
                break;
            }
        }
        catch (Exception ex) { ConsoleUI.Dim($"  Win32_OperatingSystem boot/install lookup failed: {ex.Message}"); }

        // Fallback for boot time.
        if (pc.BootTime == null)
        {
            try { pc.BootTime = DateTime.Now - TimeSpan.FromMilliseconds(Environment.TickCount64); }
            catch { /* ignore */ }
        }
    }

    private static void FillLastGameTime(PcInfo pc)
    {
        // Best signal for "last game launched" without parsing logs:
        //   newest mtime of javaw.exe / java.exe / *minecraft* prefetch entry.
        try
        {
            var pf = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
            if (!Directory.Exists(pf)) return;

            DateTime? best = null;
            foreach (var f in Directory.EnumerateFiles(pf, "*.pf"))
            {
                var n = Path.GetFileName(f);
                if (!IsGamePrefetch(n)) continue;
                try
                {
                    var ts = File.GetLastWriteTime(f);
                    if (best == null || ts > best) best = ts;
                }
                catch { /* ignore */ }
            }
            pc.LastGameTime = best;
        }
        catch (Exception ex) { ConsoleUI.Dim($"  Prefetch read failed: {ex.Message}"); }

        static bool IsGamePrefetch(string fileName)
        {
            var lower = fileName.ToLowerInvariant();
            return lower.StartsWith("javaw.exe-") ||
                   lower.StartsWith("java.exe-") ||
                   lower.Contains("minecraft") ||
                   lower.Contains("launcher");
        }
    }

    private static void FillLastRecycleTime(PcInfo pc)
    {
        try
        {
            DateTime? best = null;
            foreach (var d in DriveInfo.GetDrives())
            {
                if (d.DriveType != DriveType.Fixed || !d.IsReady) continue;
                var rb = Path.Combine(d.RootDirectory.FullName, "$Recycle.Bin");
                if (!Directory.Exists(rb)) continue;
                try
                {
                    foreach (var sub in Directory.EnumerateDirectories(rb))
                    {
                        try
                        {
                            foreach (var f in Directory.EnumerateFileSystemEntries(sub))
                            {
                                try
                                {
                                    var ts = File.GetLastWriteTime(f);
                                    if (best == null || ts > best) best = ts;
                                }
                                catch { /* ignore */ }
                            }
                        }
                        catch { /* ignore one user-sid folder */ }
                    }
                }
                catch { /* ignore one drive */ }
            }
            pc.LastRecycle = best;
        }
        catch (Exception ex) { ConsoleUI.Dim($"  Recycle Bin mtime probe failed: {ex.Message}"); }
    }

    private static readonly string[] _vpnAdapterMarkers = new[]
    {
        "tap-windows", "tap-win32", "wireguard", "openvpn",
        "tunnelbear", "nordvpn", "expressvpn", "pia", "private internet access",
        "hideguard", "mullvad", "protonvpn", "cyberghost", "windscribe",
        "softether", "zerotier", "tailscale", "hamachi", "ivpn", "surfshark",
    };

    private static readonly string[] _vpnServiceMarkers = new[]
    {
        "openvpn", "wireguard", "tunnel", "nordvpn", "expressvpn",
        "pia", "tunnelbear", "mullvad", "protonvpn", "cyberghost",
        "windscribe", "softether", "zerotier", "tailscale", "hamachi",
        "surfshark", "ivpn",
    };

    private static void FillVpn(PcInfo pc)
    {
        var hits = new List<string>();
        try
        {
            using var s = new ManagementObjectSearcher(
                "SELECT Name, Description, NetEnabled FROM Win32_NetworkAdapter");
            foreach (ManagementObject o in s.Get())
            {
                var name = (o["Name"]?.ToString() ?? "").ToLowerInvariant();
                var desc = (o["Description"]?.ToString() ?? "").ToLowerInvariant();
                var enabled = false;
                try { enabled = (bool)(o["NetEnabled"] ?? false); } catch { /* property may be missing */ }

                foreach (var m in _vpnAdapterMarkers)
                {
                    if (name.Contains(m) || desc.Contains(m))
                    {
                        hits.Add($"adapter '{o["Name"]}' [{m}{(enabled ? ", enabled" : "")}]");
                        break;
                    }
                }
            }
        }
        catch (Exception ex) { ConsoleUI.Dim($"  WMI Win32_NetworkAdapter failed: {ex.Message}"); }

        try
        {
            using var s = new ManagementObjectSearcher(
                "SELECT Name, DisplayName, State, StartMode FROM Win32_Service");
            foreach (ManagementObject o in s.Get())
            {
                var name = (o["Name"]?.ToString() ?? "").ToLowerInvariant();
                var disp = (o["DisplayName"]?.ToString() ?? "").ToLowerInvariant();
                var state = o["State"]?.ToString() ?? "";
                foreach (var m in _vpnServiceMarkers)
                {
                    if (name.Contains(m) || disp.Contains(m))
                    {
                        hits.Add($"service '{o["DisplayName"]}' [{m}, {state}]");
                        break;
                    }
                }
            }
        }
        catch (Exception ex) { ConsoleUI.Dim($"  WMI Win32_Service failed: {ex.Message}"); }

        pc.VpnHits.AddRange(hits.Distinct(StringComparer.OrdinalIgnoreCase));
        pc.VpnStatus = pc.VpnHits.Count == 0
            ? "no"
            : $"possible ({pc.VpnHits.Count} signal(s))";
    }

    private static void FillDiscord(SessionReport report, PcInfo pc)
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        var variants = new (string Variant, string Path)[]
        {
            ("Discord",            Path.Combine(localApp, "Discord")),
            ("Discord (Canary)",   Path.Combine(localApp, "DiscordCanary")),
            ("Discord (PTB)",      Path.Combine(localApp, "DiscordPTB")),
            ("Discord (Dev)",      Path.Combine(localApp, "DiscordDevelopment")),
            ("Discord (Roaming)",  Path.Combine(roaming, "discord")),
        };

        var lines = new List<string>();
        foreach (var (variant, path) in variants)
        {
            if (!Directory.Exists(path)) continue;

            string? version = TryReadDiscordVersion(path);
            bool running = IsDiscordRunning(variant);

            report.DiscordInstalls.Add(new DiscordInstall(
                Variant: variant,
                InstallPath: path,
                Version: version,
                IsRunning: running));

            lines.Add($"{variant}{(version != null ? " " + version : "")}{(running ? " (running)" : "")}");
        }

        pc.DiscordInstall = lines.Count == 0 ? null : string.Join(", ", lines);
    }

    private static string? TryReadDiscordVersion(string installRoot)
    {
        try
        {
            var dirs = Directory.EnumerateDirectories(installRoot, "app-*");
            string? best = null;
            foreach (var d in dirs)
            {
                var n = Path.GetFileName(d);
                if (n.StartsWith("app-", StringComparison.OrdinalIgnoreCase) &&
                    (best == null || string.CompareOrdinal(n, best) > 0))
                    best = n;
            }
            return best?.Substring("app-".Length);
        }
        catch { return null; }
    }

    private static bool IsDiscordRunning(string variant)
    {
        // We use WMI elsewhere; here Process.GetProcessesByName is fine and
        // doesn't read any Discord data.
        var procName = variant switch
        {
            "Discord (Canary)" => "DiscordCanary",
            "Discord (PTB)"    => "DiscordPTB",
            "Discord (Dev)"    => "DiscordDevelopment",
            _                   => "Discord",
        };
        try { return Process.GetProcessesByName(procName).Length > 0; }
        catch { return false; }
    }

    // ---------------------------------------------------------------------

    private static string BuildSummary(PcInfo pc)
    {
        var lines = new List<string>();
        if (pc.System         != null) lines.Add($"System       : {pc.System}");
        if (pc.BootTime       != null) lines.Add($"Boot time    : {pc.BootTime:yyyy-MM-dd HH:mm:ss}");
        if (pc.InstallDate    != null) lines.Add($"Install date : {pc.InstallDate:yyyy-MM-dd HH:mm:ss}");
        if (pc.Country        != null) lines.Add($"Country      : {pc.Country}");
        if (pc.TimeZone       != null) lines.Add($"Time zone    : {pc.TimeZone}");
        if (pc.Cpu            != null) lines.Add($"CPU          : {pc.Cpu}");
        if (pc.Gpu            != null) lines.Add($"GPU          : {pc.Gpu}");
        if (pc.RamBytes       != null) lines.Add($"RAM          : {FormatBytes(pc.RamBytes.Value)}");
        if (pc.LastGameTime   != null) lines.Add($"Last game    : {pc.LastGameTime:yyyy-MM-dd HH:mm:ss}");
        if (pc.LastRecycle    != null) lines.Add($"Last recycle : {pc.LastRecycle:yyyy-MM-dd HH:mm:ss}");
        if (pc.VpnStatus      != null) lines.Add($"VPN          : {pc.VpnStatus}");
        if (pc.DiscordInstall != null) lines.Add($"Discord      : {pc.DiscordInstall}");
        return string.Join("\n", lines);
    }

    private static string Ago(DateTime when)
    {
        var diff = DateTime.Now - when;
        if (diff < TimeSpan.Zero) return when.ToString("yyyy-MM-dd HH:mm");
        if (diff < TimeSpan.FromMinutes(1))  return $"{(int)diff.TotalSeconds}s ago";
        if (diff < TimeSpan.FromHours(1))    return $"{(int)diff.TotalMinutes}m ago";
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
}
