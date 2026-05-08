using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace McSsCheck.Util;

internal static class HashUtil
{
    public static string Sha256OfFile(string path)
    {
        using var sha = SHA256.Create();
        using var fs = File.OpenRead(path);
        return ToHex(sha.ComputeHash(fs));
    }

    public static string Sha1OfFile(string path)
    {
        using var sha = SHA1.Create();
        using var fs = File.OpenRead(path);
        return ToHex(sha.ComputeHash(fs));
    }

    /// <summary>Computes both SHA-256 and SHA-1 in a single pass over the file.</summary>
    public static (string Sha256, string Sha1) Sha256AndSha1OfFile(string path)
    {
        using var sha256 = SHA256.Create();
        using var sha1   = SHA1.Create();
        using var fs = File.OpenRead(path);
        var buf = new byte[81920];
        int n;
        while ((n = fs.Read(buf, 0, buf.Length)) > 0)
        {
            sha256.TransformBlock(buf, 0, n, null, 0);
            sha1  .TransformBlock(buf, 0, n, null, 0);
        }
        sha256.TransformFinalBlock(System.Array.Empty<byte>(), 0, 0);
        sha1  .TransformFinalBlock(System.Array.Empty<byte>(), 0, 0);
        return (ToHex(sha256.Hash!), ToHex(sha1.Hash!));
    }

    private static string ToHex(byte[] bytes)
    {
        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}
