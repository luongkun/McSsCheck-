using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace McSsCheck.Util;

/// <summary>
/// Reads <c>META-INF/MANIFEST.MF</c> out of a .jar / .zip and exposes the
/// attribute values the cheat heuristics care about:
///
/// <list type="bullet">
/// <item><c>Premain-Class</c> / <c>Agent-Class</c> — the bootstrap class a
///   Java agent declares so the JVM loads it via <c>-javaagent:</c>.
///   Legitimate Minecraft mods (Fabric / Forge / NeoForge / Quilt / vanilla)
///   never use <c>java.lang.instrument</c> — every cheat-agent sample we've
///   seen on screenshare (Doomsday, Weave, Konas-style loaders, Atermys jar
///   builds, …) declares at least one of these. Detecting them catches
///   even <i>repacked + renamed</i> cheat agents that no name / hash list
///   could match.</item>
/// <item><c>Main-Class</c> — useful for flagging "jar that boots straight
///   into a cheat package".</item>
/// <item><c>Can-Retransform-Classes</c> / <c>Can-Redefine-Classes</c> —
///   the two attributes a well-behaved agent-mode cheat enables so its
///   bytecode hooks survive class loading order.</item>
/// </list>
///
/// Manifests are parsed with the tiny subset of the JAR-manifest spec we
/// need: CRLF-separated key/value lines with continuation lines beginning
/// with a single space. Values longer than one line are joined.
/// </summary>
internal static class JarManifestInspector
{
    /// <summary>A manifest value. <see cref="Raw"/> is the concatenated
    /// string as written in the manifest (continuation lines joined, no
    /// trailing whitespace).</summary>
    public sealed record Attribute(string Key, string Raw);

    /// <summary>
    /// Parse the MANIFEST.MF of the given archive. Returns <c>null</c>
    /// when the archive is unreadable or has no manifest.
    /// Keys are case-insensitive; values are trimmed.
    /// </summary>
    public static Dictionary<string, string>? Read(string jarPath)
    {
        try
        {
            using var zip = ZipFile.OpenRead(jarPath);
            ZipArchiveEntry? manifest = null;
            foreach (var e in zip.Entries)
            {
                // JAR spec: META-INF/MANIFEST.MF is case-insensitive.
                if (string.Equals(e.FullName, "META-INF/MANIFEST.MF", StringComparison.OrdinalIgnoreCase))
                {
                    manifest = e;
                    break;
                }
            }
            if (manifest == null) return null;

            using var stream = manifest.Open();
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            var text = reader.ReadToEnd();
            return ParseManifest(text);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Raw manifest text parser. Public for unit-testability / reuse.
    /// </summary>
    public static Dictionary<string, string> ParseManifest(string text)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(text)) return result;

        // JAR manifests are CRLF-delimited. Continuation lines begin with a
        // single leading space; we join them onto the previous value.
        var lines = text.Replace("\r\n", "\n").Split('\n');
        string? currentKey = null;
        var currentValue = new StringBuilder();

        void Commit()
        {
            if (currentKey == null) return;
            result[currentKey] = currentValue.ToString().Trim();
            currentKey = null;
            currentValue.Clear();
        }

        foreach (var line in lines)
        {
            if (line.Length == 0) { Commit(); continue; }

            if (line[0] == ' ')
            {
                // Continuation of the previous attribute.
                currentValue.Append(line, 1, line.Length - 1);
                continue;
            }

            // New attribute — commit the previous one first.
            Commit();

            int colon = line.IndexOf(':');
            if (colon <= 0) continue;
            currentKey = line.Substring(0, colon).Trim();
            currentValue.Append(line.Substring(colon + 1).TrimStart());
        }
        Commit();

        return result;
    }

    /// <summary>
    /// True when the jar declares a Java instrumentation agent
    /// (<c>Premain-Class</c> for <c>-javaagent:</c> or <c>Agent-Class</c>
    /// for attach-API loading).
    /// </summary>
    public static bool IsJavaAgent(IReadOnlyDictionary<string, string> manifest)
        => manifest.ContainsKey("Premain-Class") || manifest.ContainsKey("Agent-Class");
}
