using System;

namespace McSsCheck.Util;

internal static class ConsoleUI
{
    private static readonly object _lock = new();

    public static void Banner(string title)
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

    public static void Section(string title)
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

    public static void Info(string text)
    {
        lock (_lock) { Console.WriteLine($"  {text}"); }
    }

    public static void Ok(string text)
    {
        lock (_lock)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  [OK] {text}");
            Console.ForegroundColor = prev;
        }
    }

    public static void Warn(string text)
    {
        lock (_lock)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.DarkYellow;
            Console.WriteLine($"  [!]  {text}");
            Console.ForegroundColor = prev;
        }
    }

    public static void Hit(string text)
    {
        lock (_lock)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [HIT] {text}");
            Console.ForegroundColor = prev;
        }
    }

    public static void Error(string text)
    {
        lock (_lock)
        {
            var prev = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  [ERR] {text}");
            Console.ForegroundColor = prev;
        }
    }

    public static void Dim(string text)
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
