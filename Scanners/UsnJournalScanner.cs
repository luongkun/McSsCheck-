using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using McSsCheck.Data;
using McSsCheck.Models;
using McSsCheck.Util;

namespace McSsCheck.Scanners;

/// <summary>
/// Reads the NTFS USN (Update Sequence Number) journal of every fixed local volume
/// and surfaces recent <c>FILE_DELETE</c> reasons for files whose name ends in
/// .jar / .exe / .bat / .class. This is the "Recovery" feature parity with Ocean.
///
/// Requires elevation (admin) because <c>\\.\C:</c> volume handles need
/// <c>FILE_GENERIC_READ</c> + <c>FILE_SHARE_READ | FILE_SHARE_WRITE</c>.
/// Gracefully no-ops when not elevated.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class UsnJournalScanner
{
    public const string SourceName = "UsnJournalScanner";

    /// <summary>
    /// Number of recent .jar/.exe/.bat/.class deletions observed during the most
    /// recent <see cref="Run"/>. Reset to zero at the start of every run.
    /// Used by <c>HeuristicEngineScanner.GenericSelfDestruct</c> to decide
    /// whether to flag mass-deletion behaviour, without us having to emit a
    /// noisy per-file Warning card for every legitimate deletion (UNINS000.EXE,
    /// WINWORD.EXE, ZALO.EXE, …).
    /// </summary>
    public static int LastDeletedBinaryCount { get; private set; }

    private const uint GENERIC_READ                 = 0x80000000;
    private const uint FILE_SHARE_READ              = 0x00000001;
    private const uint FILE_SHARE_WRITE             = 0x00000002;
    private const uint OPEN_EXISTING                = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS   = 0x02000000;

    private const uint FSCTL_QUERY_USN_JOURNAL      = 0x000900F4;
    private const uint FSCTL_READ_USN_JOURNAL       = 0x000900BB;

    private const uint USN_REASON_FILE_DELETE       = 0x00000200;

    [StructLayout(LayoutKind.Sequential)]
    private struct USN_JOURNAL_DATA_V0
    {
        public ulong UsnJournalID;
        public long  FirstUsn;
        public long  NextUsn;
        public long  LowestValidUsn;
        public long  MaxUsn;
        public ulong MaximumSize;
        public ulong AllocationDelta;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct READ_USN_JOURNAL_DATA_V0
    {
        public long  StartUsn;
        public uint  ReasonMask;
        public uint  ReturnOnlyOnClose;
        public ulong Timeout;
        public ulong BytesToWaitFor;
        public ulong UsnJournalID;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(
        string lpFileName,
        uint   dwDesiredAccess,
        uint   dwShareMode,
        IntPtr lpSecurityAttributes,
        uint   dwCreationDisposition,
        uint   dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        IntPtr   hDevice,
        uint     dwIoControlCode,
        IntPtr   lpInBuffer,
        uint     nInBufferSize,
        IntPtr   lpOutBuffer,
        uint     nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr   lpOverlapped);

    public static void Run(SessionReport.Section section)
    {
        ConsoleUI.Section("NTFS USN Journal (recently deleted .jar/.exe/.bat)");
        LastDeletedBinaryCount = 0;

        if (!IsElevated())
        {
            ConsoleUI.Warn("Not running elevated — USN journal read requires admin. Skipping.");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Warn,
                Title: "USN journal scan skipped (not elevated)",
                Detail: "Rerun this tool as administrator to recover recently deleted .jar/.exe/.bat/.class file names from the NTFS journal."));
            return;
        }

        var drives = DriveInfo.GetDrives()
            .Where(d => d.IsReady && d.DriveType == DriveType.Fixed && d.DriveFormat == "NTFS")
            .Select(d => d.RootDirectory.FullName.TrimEnd('\\'))
            .ToList();

        if (drives.Count == 0)
        {
            ConsoleUI.Dim("No NTFS fixed drives detected.");
            return;
        }

        foreach (var drive in drives)
            ScanDrive(drive, section);
    }

    private static bool IsElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            var p = new WindowsPrincipal(id);
            return p.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static void ScanDrive(string drive, SessionReport.Section section)
    {
        var devicePath = $@"\\.\{drive}";
        ConsoleUI.Info($"  reading USN journal of {drive}");

        var handle = CreateFileW(devicePath,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            IntPtr.Zero);

        if (handle == IntPtr.Zero || handle.ToInt64() == -1)
        {
            int err = Marshal.GetLastWin32Error();
            ConsoleUI.Warn($"  cannot open {devicePath} (err={err}); skipping.");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Warn,
                Title: $"USN journal: cannot open {drive}",
                Detail: $"CreateFileW failed, win32 err={err}"));
            return;
        }

        try
        {
            // Query journal metadata
            int qSize = Marshal.SizeOf<USN_JOURNAL_DATA_V0>();
            IntPtr qOut = Marshal.AllocHGlobal(qSize);
            try
            {
                if (!DeviceIoControl(handle, FSCTL_QUERY_USN_JOURNAL,
                        IntPtr.Zero, 0, qOut, (uint)qSize, out uint qRet, IntPtr.Zero))
                {
                    int err = Marshal.GetLastWin32Error();
                    ConsoleUI.Warn($"  USN journal query failed on {drive} (err={err}); skipping.");
                    section.Add(new ScanResult(
                        Source: SourceName, Severity: Severity.Warn,
                        Title: $"USN journal query failed on {drive}",
                        Detail: $"FSCTL_QUERY_USN_JOURNAL win32 err={err}"));
                    return;
                }

                var meta = Marshal.PtrToStructure<USN_JOURNAL_DATA_V0>(qOut);

                var read = new READ_USN_JOURNAL_DATA_V0
                {
                    StartUsn          = meta.FirstUsn,
                    ReasonMask        = USN_REASON_FILE_DELETE,
                    ReturnOnlyOnClose = 1,
                    Timeout           = 0,
                    BytesToWaitFor    = 0,
                    UsnJournalID      = meta.UsnJournalID,
                };

                int rdInSize = Marshal.SizeOf<READ_USN_JOURNAL_DATA_V0>();
                IntPtr rdIn = Marshal.AllocHGlobal(rdInSize);
                Marshal.StructureToPtr(read, rdIn, false);

                const int OutBufSize = 256 * 1024;
                IntPtr outBuf = Marshal.AllocHGlobal(OutBufSize);

                try
                {
                    int found = 0;
                    int iterations = 0;

                    while (iterations < 200)  // hard cap to avoid runaway loops on huge drives
                    {
                        if (!DeviceIoControl(handle, FSCTL_READ_USN_JOURNAL,
                                rdIn, (uint)rdInSize, outBuf, OutBufSize,
                                out uint bytesReturned, IntPtr.Zero))
                        {
                            int err = Marshal.GetLastWin32Error();
                            ConsoleUI.Dim($"  USN read on {drive} stopped (err={err})");
                            break;
                        }

                        if (bytesReturned < 8) break;

                        long nextUsn = Marshal.ReadInt64(outBuf, 0);
                        IntPtr cursor = IntPtr.Add(outBuf, 8);
                        long remaining = bytesReturned - 8;

                        while (remaining > 0)
                        {
                            int recordLen   = Marshal.ReadInt32(cursor, 0);
                            if (recordLen <= 0 || recordLen > remaining) break;

                            // USN_RECORD_V2 layout (only fields we care about):
                            //   0  : RecordLength (uint)
                            //   4  : MajorVersion (ushort)
                            //   6  : MinorVersion (ushort)
                            //   ... we jump straight to FileNameLength @ offset 56, FileNameOffset @ 58
                            ushort major   = (ushort)Marshal.ReadInt16(cursor, 4);
                            uint   reason  = (uint)Marshal.ReadInt32(cursor, 40);
                            long   tsTicks = Marshal.ReadInt64(cursor, 32);
                            ushort nameLen    = (ushort)Marshal.ReadInt16(cursor, 56);
                            ushort nameOffset = (ushort)Marshal.ReadInt16(cursor, 58);

                            if (major == 2 && nameLen > 0 && (reason & USN_REASON_FILE_DELETE) != 0)
                            {
                                var nameBytes = new byte[nameLen];
                                Marshal.Copy(IntPtr.Add(cursor, nameOffset), nameBytes, 0, nameLen);
                                var fname = Encoding.Unicode.GetString(nameBytes);
                                var lower = fname.ToLowerInvariant();
                                bool relevant = lower.EndsWith(".jar")  ||
                                                lower.EndsWith(".exe")  ||
                                                lower.EndsWith(".bat")  ||
                                                lower.EndsWith(".class");

                                if (relevant)
                                {
                                    found++;
                                    LastDeletedBinaryCount++;
                                    DateTime ts;
                                    try { ts = DateTime.FromFileTime(tsTicks); }
                                    catch { ts = DateTime.MinValue; }

                                    var matched = KnownCheats.MatchKeywords(fname, KnownCheats.NameKeywords).ToList();
                                    if (matched.Count > 0)
                                    {
                                        ConsoleUI.Hit($"  deleted on {drive}: {fname}  ts={ts:yyyy-MM-dd HH:mm}  matched=[{string.Join(",", matched)}]");
                                        section.Add(new ScanResult(
                                            Source: SourceName, Severity: Severity.Hit,
                                            Title: $"Deleted file matches cheat keyword on {drive}",
                                            Detail: $"file={fname}, deleted~={ts:yyyy-MM-dd HH:mm}, matched: {string.Join(", ", matched)}",
                                            FilePath: fname, Timestamp: ts,
                                            Tags: matched.ToArray()));
                                    }
                                    // v0.8.0 noise cut: drop the "Severity.Warn per deleted binary"
                                    // pathway. Most deletions are legitimate uninstalls (UNINS000.EXE)
                                    // or app updates (WINWORD.EXE, ZALO.EXE). We still increment
                                    // LastDeletedBinaryCount above so HeuristicEngineScanner can flag
                                    // mass-deletion behaviour with a single summary card.
                                }
                            }

                            cursor = IntPtr.Add(cursor, recordLen);
                            remaining -= recordLen;
                        }

                        if (nextUsn == read.StartUsn) break;     // no progress
                        read.StartUsn = nextUsn;
                        Marshal.StructureToPtr(read, rdIn, false);
                        iterations++;
                        if (nextUsn >= meta.NextUsn) break;
                    }

                    if (found == 0)
                        ConsoleUI.Ok($"  no recently deleted .jar/.exe/.bat/.class entries on {drive}.");
                }
                finally
                {
                    Marshal.FreeHGlobal(rdIn);
                    Marshal.FreeHGlobal(outBuf);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(qOut);
            }
        }
        catch (Exception ex)
        {
            ConsoleUI.Warn($"  USN scan error on {drive}: {ex.Message}");
            section.Add(new ScanResult(
                Source: SourceName, Severity: Severity.Error,
                Title: $"USN journal scan error on {drive}",
                Detail: ex.Message));
        }
        finally
        {
            CloseHandle(handle);
        }
    }
}
