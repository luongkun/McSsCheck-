using System;
using System.IO;

namespace McSsCheck.Util;

internal static class EntropyUtil
{
    /// <summary>
    /// Shannon entropy of a byte sequence, normalized to [0, 8].
    /// Random / encrypted / packed data tends to score &gt; 7.5.
    /// Plain compiled Java bytecode hovers around 5.0 - 6.5.
    /// </summary>
    public static double Shannon(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return 0.0;
        Span<int> counts = stackalloc int[256];
        foreach (var b in data) counts[b]++;

        double entropy = 0.0;
        double len = data.Length;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            double p = counts[i] / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    /// <summary>
    /// Streams up to <paramref name="cap"/> bytes from a stream and computes entropy.
    /// </summary>
    public static double ShannonStream(Stream s, int cap = 1 << 20)
    {
        using var ms = new MemoryStream();
        var buf = new byte[8192];
        int read;
        while (ms.Length < cap && (read = s.Read(buf, 0, buf.Length)) > 0)
        {
            int toCopy = (int)Math.Min(read, cap - ms.Length);
            ms.Write(buf, 0, toCopy);
        }
        return Shannon(ms.GetBuffer().AsSpan(0, (int)ms.Length));
    }
}
