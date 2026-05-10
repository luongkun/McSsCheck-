using System.Collections.Generic;
using System.Text;

namespace McSsCheck.Util;

/// <summary>
/// Shared quote-aware tokenizer for Windows command lines (as seen in
/// <c>Win32_Process.CommandLine</c>). Replaces the identical copies that
/// were previously duplicated inside <see cref="Scanners.ProcessScanner"/>
/// and <see cref="Scanners.LiveJvmScanner"/>. Behaviour is unchanged.
///
/// The parser is intentionally simple — it only handles space-separated
/// tokens with double-quoted groups. It does NOT interpret Win32
/// backslash-quote escape rules (rare in practice for JVM cmdlines and
/// not needed for any keyword-match use the scanners do).
/// </summary>
internal static class CmdlineTokenizer
{
    public static IEnumerable<string> Tokenize(string? cmd)
    {
        if (string.IsNullOrEmpty(cmd)) yield break;

        var current = new StringBuilder();
        bool inQuotes = false;
        foreach (var c in cmd)
        {
            if (c == '"') { inQuotes = !inQuotes; continue; }
            if (char.IsWhiteSpace(c) && !inQuotes)
            {
                if (current.Length > 0) { yield return current.ToString(); current.Clear(); }
                continue;
            }
            current.Append(c);
        }
        if (current.Length > 0) yield return current.ToString();
    }
}
