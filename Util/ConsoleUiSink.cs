using System;

namespace McSsCheck.Util;

/// <summary>
/// Default <see cref="IUiSink"/> — writes to <see cref="Console"/> with
/// ANSI colours. This is exactly the behaviour the tool had before the
/// GUI was introduced; it is now reachable via <c>--console</c>.
/// </summary>
internal sealed class ConsoleUiSink : IUiSink
{
    private readonly object _lock = new();

    public void Banner(string title)
    {
        lock (_lock)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine();
            Console.WriteLine(new string('=', 78));
            Console.WriteLine($" {title}");
            Console.WriteLine(new string('=', 78));
            Console.ForegroundColor = prev;
        }
    }

    public void Section(string title)
    {
        lock (_lock)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine();
            Console.WriteLine($"--- {title} ---");
            Console.ForegroundColor = prev;
        }
    }

    public void Info(string text)
    {
        lock (_lock) { Console.WriteLine($"  {text}"); }
    }

    public void Ok(string text)
    {
        lock (_lock)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  [OK] {text}");
            Console.ForegroundColor = prev;
        }
    }

    public void Warn(string text)
    {
        lock (_lock)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine($"  [!]  {text}");
            Console.ForegroundColor = prev;
        }
    }

    public void Hit(string text)
    {
        lock (_lock)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [HIT] {text}");
            Console.ForegroundColor = prev;
        }
    }

    public void Error(string text)
    {
        lock (_lock)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [ERR] {text}");
            Console.ForegroundColor = prev;
        }
    }

    public void Dim(string text)
    {
        lock (_lock)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($"  {text}");
            Console.ForegroundColor = prev;
        }
    }
}
