using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using McSsCheck.Data;

namespace McSsCheck.Util;

/// <summary>
/// Searches a slice of file bytes for any <see cref="CheatFingerprints.BinaryMarkers"/>.
/// The match runs twice — once against the raw bytes treated as Latin-1 (ASCII)
/// and once against the bytes decoded as UTF-16-LE — so we catch both regular
/// PE strings and Windows widechar resources / .NET ldstr literals.
///
/// We never load the entire file into memory: callers pass a budget
/// (default 8 MB) and we skip the rest. Cheat banners / PDB paths /
/// branding strings always live near the top of the binary, well within
/// 1-2 MB; 8 MB is a generous ceiling that still keeps a million-jar
/// ".minecraft" walk under a second per jar.
/// </summary>
internal static class BinaryMarkerScanner
{
    /// <summary>Default cap for how many bytes we read from any one file.</summary>
    public const int DefaultByteBudget = 8 * 1024 * 1024;

    /// <summary>One match against a binary marker.</summary>
    public sealed record MarkerHit(string CheatName, string Variant, string Pattern, string Encoding);

    /// <summary>
    /// Scan a stream for every distinctive cheat marker. Reads at most
    /// <paramref name="byteBudget"/> bytes. Returns one <see cref="MarkerHit"/>
    /// per (CheatName, Variant) pair (deduplicated within a single file so
    /// we don't fire 50 cards if a marker repeats).
    /// </summary>
    public static IReadOnlyList<MarkerHit> Scan(Stream stream, int byteBudget = DefaultByteBudget)
    {
        var buf = ReadUpTo(stream, byteBudget);
        if (buf.Length == 0) return Array.Empty<MarkerHit>();

        // Treat raw bytes as Latin-1: every byte 0..255 becomes the same
        // codepoint, so substring search works for ASCII patterns at any
        // byte alignment. .IndexOf with Ordinal is the fastest path.
        string asAscii = LatinFromBytes(buf);

        var hits = new List<MarkerHit>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var marker in CheatFingerprints.BinaryMarkers)
        {
            var key = $"{marker.CheatName}|{marker.Variant}";
            if (seen.Contains(key)) continue;

            if (asAscii.Contains(marker.Pattern, StringComparison.OrdinalIgnoreCase))
            {
                hits.Add(new MarkerHit(marker.CheatName, marker.Variant, marker.Pattern, "ascii"));
                seen.Add(key);
                continue;
            }

            // UTF-16-LE: insert NUL after every byte. We do this lazily by
            // building a probe string from the pattern and scanning a
            // widechar view of the buffer. Skip very long patterns (those
            // are basically guaranteed to match the ASCII pass anyway).
            if (marker.Pattern.Length <= 64 && IndexOfUtf16Le(buf, marker.Pattern) >= 0)
            {
                hits.Add(new MarkerHit(marker.CheatName, marker.Variant, marker.Pattern, "utf16le"));
                seen.Add(key);
            }
        }

        return hits;
    }

    /// <summary>Convenience: scan an on-disk file (opens FileShare.ReadWrite).</summary>
    public static IReadOnlyList<MarkerHit> ScanFile(string path, int byteBudget = DefaultByteBudget)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            return Scan(fs, byteBudget);
        }
        catch
        {
            return Array.Empty<MarkerHit>();
        }
    }

    private static byte[] ReadUpTo(Stream s, int max)
    {
        using var ms = new MemoryStream();
        var buf = new byte[81920];
        int total = 0;
        while (total < max)
        {
            int want = Math.Min(buf.Length, max - total);
            int n = s.Read(buf, 0, want);
            if (n <= 0) break;
            ms.Write(buf, 0, n);
            total += n;
        }
        return ms.ToArray();
    }

    private static string LatinFromBytes(byte[] data)
    {
        // Latin-1: every byte maps 1:1 to a codepoint. We want this so
        // string.IndexOf can run binary patterns without re-encoding.
        var chars = new char[data.Length];
        for (int i = 0; i < data.Length; i++) chars[i] = (char)data[i];
        return new string(chars);
    }

    private static int IndexOfUtf16Le(byte[] haystack, string needle)
    {
        if (needle.Length == 0) return 0;
        int needleLen = needle.Length * 2;
        if (haystack.Length < needleLen) return -1;

        // Lower-case both sides for case-insensitive search.
        for (int i = 0; i + needleLen <= haystack.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < needle.Length; j++)
            {
                byte lo = haystack[i + j * 2];
                byte hi = haystack[i + j * 2 + 1];
                if (hi != 0) { match = false; break; }
                char actual = char.ToLowerInvariant((char)lo);
                char want   = char.ToLowerInvariant(needle[j]);
                if (actual != want) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }
}
